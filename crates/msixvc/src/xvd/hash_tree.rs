use crate::layout::PAGE_SIZE;
use crate::models::xvd::layout::{HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH};

use futures_util::Stream;
use pin_project::pin_project;
use sha2::Digest;
use thiserror::Error;
use tokio::io::{AsyncRead, ReadBuf};

use std::hint;
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

type HashEntry = [u8; HASH_ENTRY_LENGTH];
type Page = [u8; PAGE_SIZE];

#[pin_project]
struct PageStream<R> {
    #[pin]
    reader: R,

    buf: Box<Page>,
    filled: usize,
}

impl<R: AsyncRead> PageStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Box::new([0u8; PAGE_SIZE]),
            filled: 0,
        }
    }

    #[inline]
    pub fn buffer(&self) -> Option<&Page> {
        (self.filled == PAGE_SIZE).then_some(&self.buf)
    }

    pub fn poll_next_page<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<&'a Page>> {
        let mut this = self.project();

        // If the last page is fully filled, then reset the buffer.
        if *this.filled == PAGE_SIZE {
            *this.filled = 0;
        }

        while *this.filled < PAGE_SIZE {
            // `buf` contains the unfilled portion of the buffer.
            let mut buf = ReadBuf::new(&mut this.buf[*this.filled..]);

            match this.reader.as_mut().poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) if let ErrorKind::Interrupted = e.kind() => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    )));
                }
                Poll::Ready(Ok(())) => *this.filled += buf.filled().len(),
            }
        }

        // `this.filled` is exactly `PAGE_SIZE`, so return `Poll::Ready`.
        // `this.filled` doesn't need to be set to 0 because the next call to
        // `poll_next_page` will do it for us.

        Poll::Ready(Ok(this.buf))
    }
}

/// Stream over level 0 hash entries.
#[pin_project]
pub struct HashTreeStream<R> {
    #[pin]
    reader: PageStream<R>,

    remaining_hashes: usize,
    next_entry_in_page: usize,

    level_1_hashes: Box<[HashEntry]>,
    current_page: usize,
}

impl<R: AsyncRead> HashTreeStream<R> {
    #[expect(dead_code)]
    pub fn new(reader: R, level_1_hashes: Box<[HashEntry]>, level_0_hashes: usize) -> Self {
        assert_eq!(
            level_0_hashes.div_ceil(HASH_ENTRIES_IN_PAGE as usize),
            level_1_hashes.len()
        );

        Self {
            reader: PageStream::new(reader),
            remaining_hashes: level_0_hashes,
            next_entry_in_page: 0,
            level_1_hashes,
            current_page: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum HashTreeStreamError {
    #[error("IO error: {0}")]
    Io(#[from] Error),

    #[error(
        r#"hash mismatch at page {page_index}:
  expected {expected:?},
  got {got:?}"#
    )]
    HashMismatch {
        page_index: usize,
        expected: HashEntry,
        got: HashEntry,
    },
}

impl<R> Stream for HashTreeStream<R>
where
    R: AsyncRead,
{
    type Item = Result<HashEntry, HashTreeStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if *this.remaining_hashes == 0 {
            return Poll::Ready(None);
        }

        // If there are remaining hash entries in the buffer that have not been
        // returned, then return the next one and advance the counter.
        if let Some(buf) = this.reader.buffer()
            && let Some(hash) = buf
                .as_chunks::<HASH_ENTRY_LENGTH>()
                .0
                .get(*this.next_entry_in_page)
        {
            *this.next_entry_in_page += 1;
            *this.remaining_hashes -= 1;
            return Poll::Ready(Some(Ok(*hash)));
        }

        let buf = match this.reader.poll_next_page(cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(buf) => buf,
        };

        // Check that the hash of the current page is the expected one. It's fine
        // to calculate the hash here because it's a single hash, so it doesn't
        // block the thread for long.

        let expected_hash: HashEntry = this.level_1_hashes[*this.current_page];
        let hash: HashEntry = sha2::Sha256::digest(buf)[..HASH_ENTRY_LENGTH]
            .try_into()
            .unwrap();

        if hash != expected_hash {
            hint::cold_path();
            return Poll::Ready(Some(Err(HashTreeStreamError::HashMismatch {
                page_index: *this.current_page,
                expected: expected_hash,
                got: hash,
            })));
        }

        // Return the first hash of the current page, and set `next_entry_in_page`
        // to 1 so subsequent calls to `poll_next` return the next entries.

        debug_assert!(*this.remaining_hashes > 0);

        *this.next_entry_in_page = 1;
        *this.remaining_hashes -= 1;
        *this.current_page += 1;

        Poll::Ready(Some(Ok(*buf.first_chunk::<HASH_ENTRY_LENGTH>().unwrap())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::pin::pin;
    use std::task::Waker;

    #[test]
    fn test_page_stream() {
        // Fill a buffer with test data.
        let test_data: [u8; PAGE_SIZE * 3 + 84] = std::array::from_fn(|i| {
            // Make sure that the first `u8::MAX` pages are all different.
            let page = i / PAGE_SIZE;
            (page as u8).wrapping_add(i as u8)
        });

        // Create a `PageStream` over the test data.
        let mut page_stream = pin!(PageStream::new(Cursor::new(&test_data)));
        let mut cx = Context::from_waker(Waker::noop());

        // For each full page in `test_data`, check that `PageStream` returns
        // exactly the same data.
        for chunk in test_data.as_chunks::<PAGE_SIZE>().0 {
            match page_stream.as_mut().poll_next_page(&mut cx) {
                Poll::Ready(Ok(buf)) => assert_eq!(buf, chunk),
                _ => unreachable!("An in-memory Cursor mustn't block nor fail"),
            }
        }

        // After we've consumed every full page, the stream must return an
        // `io::ErrorKind::UnexpectedEof` error.
        match page_stream.as_mut().poll_next_page(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            _ => unreachable!("After consuming all the pages, it must return an error"),
        }
    }
}
