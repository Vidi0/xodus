use crate::layout::PAGE_SIZE;
use crate::models::xvd::layout::{HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH};

use futures_util::Stream;
use pin_project::pin_project;
use sha2::Digest;
use thiserror::Error;
use tokio::io::{AsyncRead, ReadBuf};

use std::cmp;
use std::collections::VecDeque;
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

    pub fn poll_next_page<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<&'a Page>> {
        let mut this = self.project();

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

        // `this.filled` is exactly `PAGE_SIZE`, so return the page buffer. The
        // buffer doesn't need to be zeroed because we set `this.filled` to 0,
        // so every byte is treated as garbage.

        *this.filled = 0;

        Poll::Ready(Ok(this.buf))
    }
}

/// Stream over level 0 hash entries.
#[pin_project]
pub struct HashTreeStream<R> {
    #[pin]
    reader: PageStream<R>,

    level_1_hashes: Box<[HashEntry]>,
    current_page: usize,

    remaining_hashes: usize,
    parsed_entries: VecDeque<HashEntry>,
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
            level_1_hashes,
            current_page: 0,
            remaining_hashes: level_0_hashes,
            parsed_entries: VecDeque::with_capacity(HASH_ENTRIES_IN_PAGE as usize),
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

        if let Some(hash) = this.parsed_entries.pop_front() {
            return Poll::Ready(Some(Ok(hash)));
        }

        if *this.remaining_hashes == 0 {
            return Poll::Ready(None);
        }

        let buf = match this.reader.poll_next_page(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(Ok(buf)) => buf,
        };

        // Check that the hash of the current page is the expected one. It's fine
        // to calculate the hash here because it's a single hash, so it doesn't
        // block the thread for long.

        let expected_hash: HashEntry = this.level_1_hashes[*this.current_page];
        let hash: HashEntry = sha2::Sha256::digest(buf)[..HASH_ENTRY_LENGTH]
            .try_into()
            .unwrap();

        if hash != expected_hash {
            return Poll::Ready(Some(Err(HashTreeStreamError::HashMismatch {
                page_index: *this.current_page,
                expected: expected_hash,
                got: hash,
            })));
        }

        // Parse the current page and reset the buffer.

        assert!(*this.remaining_hashes > 0);
        let hashes_to_parse = cmp::min(*this.remaining_hashes, HASH_ENTRIES_IN_PAGE as usize);

        let mut hash_entry_iter = buf
            .as_chunks::<HASH_ENTRY_LENGTH>()
            .0
            .iter()
            .copied()
            .take(hashes_to_parse);

        // Obtain the first hash entry independently, as it will be returned at
        // the end of the function. It is guaranteed that there is at least one
        // remaining hash entry.
        let first = hash_entry_iter
            .next()
            .expect("there must be at least one remaining hash entry");

        // Push the remaining entries into the `parsed_entries` buffer so they
        // are returned in the following calls to `poll_next`.
        this.parsed_entries.extend(hash_entry_iter);

        *this.remaining_hashes -= hashes_to_parse;
        *this.current_page += 1;

        Poll::Ready(Some(Ok(first)))
    }
}
