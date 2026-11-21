pub mod models;

use models::XvdHeader;
use msixvc_common::parse::BinaryTryParse;

use std::borrow::Borrow;

use rsa::PublicKey;
use rsa::sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE_SIZE: usize = 512;
const HEADER_SIZE_TOTAL: usize = 4096;

/// A struct that only lets access to the data after it has beed verified.
///
/// To try a public key, use [`Self::unlock`].
///
/// To try multiple public keys, use [`Self::unlock_any`].
///
/// To dismiss the verification and obtain the underlying value without
/// checking its integrity, see [`Self::dismiss`].
#[derive(Debug)]
pub struct Verifier<T> {
    signature: [u8; SIGNATURE_SIZE],
    hash: [u8; 32],
    value: T,
}

impl<T> Verifier<T> {
    fn new(signature: [u8; SIGNATURE_SIZE], data: &[u8], value: T) -> Self {
        Verifier {
            signature,
            hash: Sha256::digest(data).0,
            value,
        }
    }

    /// Dismiss the verifier, so the underlying value is returned without
    /// checking its integrity.
    pub fn dismiss(self) -> T {
        self.value
    }

    /// Check whether the provided key verifies the underlying data.
    pub fn check(&self, key: &PublicKey) -> bool {
        key.pss_verify_prehash::<Sha256>(&self.hash, &self.signature)
            .is_ok()
    }

    /// Try to unlock the verifier with the provided public key.
    #[expect(clippy::result_large_err)]
    pub fn unlock(self, key: &PublicKey) -> Result<T, Self> {
        if self.check(key) {
            Ok(self.value)
        } else {
            Err(self)
        }
    }

    /// Try to unlock the verifier with any of the provided public keys, in
    /// order.
    #[expect(clippy::result_large_err)]
    pub fn unlock_any<I>(self, keys: I) -> Result<T, Self>
    where
        I: IntoIterator,
        I::Item: Borrow<PublicKey>,
    {
        for key in keys {
            if self.check(key.borrow()) {
                return Ok(self.value);
            }
        }

        Err(self)
    }
}

#[derive(Debug, Error)]
pub enum ReadHeaderError {
    #[error("I/O error: {0}")]
    Io(#[from] tokio::io::Error),

    #[error("invalid header struct: {0}")]
    Parse(#[from] models::XvdHeaderParseError),
}

pub async fn read_header<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Verifier<XvdHeader>, ReadHeaderError> {
    let mut buf = [0u8; HEADER_SIZE_TOTAL];
    reader.read_exact(&mut buf).await?;

    // It won't panic because `SIGNATURE_SIZE` is less than `HEADER_TOTAL_SIZE`,
    // and the remaining bytes are exactly `XvdHeader::SIZE`.

    let (signature, header_slice) = buf.split_first_chunk::<SIGNATURE_SIZE>().unwrap();
    let header = XvdHeader::try_from_slice(header_slice)?;

    // Wrap the header into a verifier struct that only returns its contents
    // when the header bytes have been verified by the appropiate RSA signature.

    let verifier = Verifier::new(*signature, header_slice, header);

    Ok(verifier)
}
