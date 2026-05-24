use crate::tlv::TLV;
use std::io::{self, Read};

const MAGIC: [u8; 4] = *b"EKB1";

pub struct EKB {}

impl EKB {
    pub fn from_reader<R: Read>(mut reader: R) -> io::Result<Self> {
        {
            let mut magic = [0u8; 4];
            reader.read_exact(&mut magic)?;

            if magic != MAGIC {
                panic!("magic mismatch");
            }
        }

        let length = {
            let mut length = [0u8; 4];
            reader.read_exact(&mut length)?;
            u32::from_le_bytes(length)
        };

        let data = {
            let mut bytes = vec![0u8; length as usize];
            reader.read_exact(&mut bytes)?;
            bytes
        };

        let tlvs = TLV::decode_all(&data)?;

        println!("tlvs:");

        for tlv in tlvs {
            println!("{tlv:?}");
        }

        Ok(Self {})
    }
}
