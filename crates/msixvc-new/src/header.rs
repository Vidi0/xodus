pub mod models;

use models::XvdHeader;
use msixvc_common::parse::BinaryTryParse;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE_SIZE: usize = 512;
const HEADER_SIZE_TOTAL: usize = 4096;

#[derive(Debug, Error)]
pub enum ReadHeaderError {
    #[error("I/O error: {0}")]
    Io(#[from] tokio::io::Error),

    #[error("invalid header struct: {0}")]
    Parse(#[from] models::XvdHeaderParseError),
}

pub async fn read_header<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<([u8; 512], XvdHeader), ReadHeaderError> {
    let mut buf = [0u8; HEADER_SIZE_TOTAL];
    reader.read_exact(&mut buf).await?;

    // It won't panic because `SIGNATURE_SIZE` is less than `HEADER_TOTAL_SIZE`,
    // and the remaining bytes are exactly `XvdHeader::SIZE`.

    let (signature, header_slice) = buf.split_first_chunk::<SIGNATURE_SIZE>().unwrap();
    let header = XvdHeader::try_from_slice(header_slice)?;

    Ok((*signature, header))
}
