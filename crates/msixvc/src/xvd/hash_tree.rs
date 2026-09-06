use crate::layout::PAGE_SIZE;
use crate::models::xvd::layout::{HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH};

use futures_util::Stream;
use pin_project::pin_project;
use sha2::Digest;
use thiserror::Error;
use tokio::io::{AsyncRead, ReadBuf};

use std::cmp;
use std::collections::VecDeque;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

type HashEntry = [u8; HASH_ENTRY_LENGTH];

/// Stream over level 0 hash entries.
#[pin_project]
pub struct HashTreeStream<R> {
    #[pin]
    reader: R,

    buf: Box<[u8; PAGE_SIZE]>,
    filled: usize,

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
            reader,
            buf: Box::new([0u8; PAGE_SIZE]),
            filled: 0,
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
        let mut this = self.project();

        if let Some(hash) = this.parsed_entries.pop_front() {
            return Poll::Ready(Some(Ok(hash)));
        }

        if *this.remaining_hashes == 0 {
            return Poll::Ready(None);
        }

        while *this.filled < PAGE_SIZE {
            let mut buf = ReadBuf::new(&mut this.buf[*this.filled..]);

            match this.reader.as_mut().poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) if let ErrorKind::Interrupted = e.kind() => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(Ok(())) => {
                    let advanced = buf.filled().len();
                    *this.filled += advanced;

                    if advanced == 0 {
                        return Poll::Ready(Some(Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "failed to fill whole buffer",
                        )
                        .into())));
                    }
                }
            }
        }

        // `this.filled` is exactly `PAGE_SIZE`, so check that the hash of the
        // current page is the expected one. It's fine to calculate the hash
        // here because it's a single hash, so it doesn't block the thread for long.

        let expected_hash: HashEntry = this.level_1_hashes[*this.current_page];
        let hash: HashEntry = sha2::Sha256::digest(**this.buf)[..HASH_ENTRY_LENGTH]
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

        let mut hash_entry_iter = this
            .buf
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

        // We don't need to zero `buf` because we set `filled` to 0, so the
        // remaining bytes are allowed to be garbage.
        *this.filled = 0;
        *this.remaining_hashes -= hashes_to_parse;
        *this.current_page += 1;

        Poll::Ready(Some(Ok(first)))
    }
}
