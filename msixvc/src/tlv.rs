use std::io::{self, Read};

/// A TLV is decoded from a reader and encodes a tag, a length and a value.
#[derive(Debug)]
pub struct TLV {
    pub tag: u16,
    pub value: Box<[u8]>,
}

impl TLV {
    pub fn from_reader<R: Read>(mut reader: R) -> io::Result<Self> {
        let tag = {
            let mut bytes = [0u8; 2];
            reader.read_exact(&mut bytes)?;
            u16::from_le_bytes(bytes)
        };

        let length = {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            u32::from_le_bytes(bytes)
        };

        let value = {
            let mut bytes = vec![0u8; length as usize].into_boxed_slice();
            reader.read_exact(&mut bytes)?;
            bytes
        };

        Ok(Self { tag, value })
    }

    pub fn decode_all(mut data: &[u8]) -> io::Result<Vec<Self>> {
        let mut tlvs = Vec::new();

        loop {
            if data.is_empty() {
                break Ok(tlvs);
            }

            let tlv = TLV::from_reader(&mut data)?;
            tlvs.push(tlv);
        }
    }
}
