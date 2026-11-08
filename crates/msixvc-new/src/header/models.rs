use crate::layout::*;

use msixvc_common::parse::byteorder::little_endian::*;
use msixvc_common::parse::structs::{Filetime, Version};
use msixvc_common::parse::{BinaryParse, BinaryTryParse, BytesReader, EmptyReader};

use bitflags::bitflags;
use chrono::DateTime;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;
use typenum::{Diff, Sum};
use uuid::Uuid;

use std::fmt::Debug;
use std::ops::RangeBounds;

// Flags

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XvdVolumeFlags: u32 {
        const READ_ONLY = 1 << 0;
        const ENCRYPTION_DISABLED = 1 << 1;
        const DATA_INTEGRITY_DISABLED = 1 << 2;
        const LEGACY_SECTOR_SIZE = 1 << 3;
        const RESILIENCY_ENABLED = 1 << 4;
        const SRA_READ_ONLY = 1 << 5;
        const REGION_ID_IN_XTS = 1 << 6;
        const ERA_SPECIFIC = 1 << 7;
    }
}

impl BinaryParse for XvdVolumeFlags {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (flags, r) = r.read::<U32>();
        (XvdVolumeFlags::from_bits_retain(flags), r)
    }
}

impl XvdVolumeFlags {
    pub fn is_encrypted(&self) -> bool {
        !self.contains(Self::ENCRYPTION_DISABLED)
    }

    pub fn is_legacy_sector_size(&self) -> bool {
        self.contains(Self::LEGACY_SECTOR_SIZE)
    }

    pub fn is_data_integrity_enabled(&self) -> bool {
        !self.contains(Self::DATA_INTEGRITY_DISABLED)
    }

    pub fn is_resiliency_enabled(&self) -> bool {
        self.contains(Self::RESILIENCY_ENABLED)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WriteablePolicyFlags: u32 {}
}

impl BinaryParse for WriteablePolicyFlags {
    type Output = Self;
    type Size = typenum::U4;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, EmptyReader<'a>) {
        let (flags, r) = r.read::<U32>();
        (WriteablePolicyFlags::from_bits_retain(flags), r)
    }
}

// Enums

// These enums are `repr(u8)`, but they implement `BinaryParse` or `BinaryTryParse`
// for a size of 4 bytes because they are stored as u32 on the wire.

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum XvdType {
    Fixed = 0,
    Dynamic = 1,
}

impl BinaryTryParse for XvdType {
    type Output = Self;
    type Size = typenum::U4;
    type Error = <Self as TryFrom<u8>>::Error;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (val, r) = r.read::<U32>();
        Self::try_from(val as u8).map(|val| (val, r))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum XvdContentType {
    Data = 0,
    Title = 1,
    SystemOS = 2,
    EraOS = 3,
    Scratch = 4,
    ResetData = 5,
    Application = 6,
    HostOS = 7,
    X360STFS = 8,
    X360FATX = 9,
    X360GDFX = 0xA,
    Updater = 0xB,
    OfflineUpdater = 0xC,
    Template = 0xD,
    MteHost = 0xE,
    MteApp = 0xF,
    MteTitle = 0x10,
    MteEraOS = 0x11,
    EraTools = 0x12,
    SystemTools = 0x13,
    SystemAux = 0x14,
    AcousticModel = 0x15,
    SystemCodecsVolume = 0x16,
    QasltPackage = 0x17,
    AppDlc = 0x18,
    TitleDlc = 0x19,
    UniversalDlc = 0x1A,
    SystemDataVolume = 0x1B,
    TestVolume = 0x1C,
    HardwareTestVolume = 0x1D,
    KioskContent = 0x1E,
    HostProfiler = 0x20,
    Uwa = 0x21,
    Unknown22 = 0x22,
    Unknown23 = 0x23,
    Unknown24 = 0x24,
    ServerAgent = 0x25,
}

impl BinaryTryParse for XvdContentType {
    type Output = Self;
    type Size = typenum::U4;
    type Error = <Self as TryFrom<u8>>::Error;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, EmptyReader<'a>), Self::Error> {
        let (val, r) = r.read::<U32>();
        Self::try_from(val as u8).map(|val| (val, r))
    }
}

// Structs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XvdExtEntry {
    pub code: u32,
    pub length: u32,
    pub offset: u64,
    pub data_length: u32,
}

impl BinaryParse for XvdExtEntry {
    type Output = Self;
    type Size = typenum::U24;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self, EmptyReader<'a>) {
        let (code, r) = r.read::<U32>();
        let (length, r) = r.read::<U32>();
        let (offset, r) = r.read::<U64>();
        let (data_length, r) = r.read::<U32>();
        let (_reserved, r) = r.read::<U32>();

        (
            Self {
                code,
                length,
                offset,
                data_length,
            },
            r,
        )
    }
}

// The header does not include the signature
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XvdHeader {
    pub volume_flags: XvdVolumeFlags,
    pub format_version: u32,
    pub file_time_created: DateTime<chrono::Utc>,
    pub drive_size: Bytes,
    pub vduid: Uuid,
    pub uduid: Uuid,
    pub top_hash_block_hash: [u8; 0x20],
    pub original_xvc_data_hash: [u8; 0x20],
    pub xvd_type: XvdType,
    pub xvd_content_type: XvdContentType,
    pub embedded_xvd_length: Bytes,
    pub user_data_length: Bytes,
    pub xvc_data_length: Bytes,
    pub dynamic_header_length: Bytes,
    pub block_size: u32,
    pub ext_entries: [XvdExtEntry; 0x4],
    pub capabilities: [u16; 0x8],
    pub pe_catalog_hash: [u8; 0x20],
    pub embedded_xvd_pduid: Uuid,
    pub key_material: [u8; 0x20],
    pub user_data_hash: [u8; 0x20],
    pub sandbox_id: [u8; 0x10],
    pub product_id: Uuid,
    pub pduid: Uuid,
    pub package_version: Version,
    pub pe_catalog_caps: [u16; 0x10],
    pub pe_catalogs: [u8; 0x80],
    pub writeable_expiration_date: u32,
    pub writeable_policy_flags: WriteablePolicyFlags,
    pub persistent_local_storage_size: u32,
    pub mutable_page_count: Pages,
    pub sequence_number: i64,
    pub required_system_version: Version,
    pub odk_keyslot_id: u32,
    pub resilient_data_offset: u64,
    pub resilient_data_length: u32,
}

impl XvdHeader {
    const MAGIC: &[u8; 8] = b"msft-xvd";
}

// TODO: REMOVE THIS
const MAX_HASHED_PAGES: Pages = Pages(1);

#[derive(Error, Debug)]
pub enum XvdHeaderParseError {
    #[error(r#"invalid magic: expected {magic:?}, got {0:?}"#, magic = XvdHeader::MAGIC)]
    InvalidMagic([u8; 8]),

    #[error("invalid xvd type: {0}")]
    InvalidXvdType(#[from] TryFromPrimitiveError<XvdType>),

    #[error("invalid xvd content type: {0}")]
    InvalidXvdContentType(#[from] TryFromPrimitiveError<XvdContentType>),

    #[error("out of bounds value for variable \"{variable}\": {value}")]
    OutOfBounds { variable: &'static str, value: u64 },

    #[error("invalid hashed pages count: {hashed_pages:?}, must be less than {MAX_HASHED_PAGES:?}")]
    InvalidHashedPagesCount { hashed_pages: Pages },
}

macro_rules! check_bounds {
    ($name:ident, $read:expr, $range:expr) => {
        let $name = $read?;
        if !($range).contains(&$name) {
            return Err(Error::OutOfBounds {
                variable: stringify!($name),
                value: Box::new($name),
            });
        }
    };
}

fn check_bounds(
    value: u64,
    bounds: impl RangeBounds<u64>,
    variable_name: &'static str,
) -> Result<u64, XvdHeaderParseError> {
    if bounds.contains(&value) {
        Ok(value)
    } else {
        Err(XvdHeaderParseError::OutOfBounds {
            variable: variable_name,
            value,
        })
    }
}

impl BinaryTryParse for XvdHeader {
    type Output = Self;
    type Size = Diff<typenum::U4096, typenum::U512>;
    type Error = XvdHeaderParseError;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self, EmptyReader<'a>), Self::Error> {
        let r = r.magic(Self::MAGIC).map_err(Self::Error::InvalidMagic)?;

        let (volume_flags, r) = r.read::<XvdVolumeFlags>();
        let (format_version, r) = r.read::<U32>();
        let (file_time_created, r) = r.read::<Filetime>();
        let (drive_size, r) = r.read::<BytesParse<U64>>();

        let (vduid, r) = r.read::<Uuid>();
        let (uduid, r) = r.read::<Uuid>();

        let (top_hash_block_hash, r) = r.array::<0x20>();
        let (original_xvc_data_hash, r) = r.array::<0x20>();

        let (xvd_type, r) = r.try_read::<XvdType>()?;
        let (xvd_content_type, r) = r.try_read::<XvdContentType>()?;

        let (embedded_xvd_length, r) = r.read::<BytesParse<U32>>();
        let (user_data_length, r) = r.read::<BytesParse<U32>>();
        let (xvc_data_length, r) = r.read::<BytesParse<U32>>();
        let (dynamic_header_length, r) = r.read::<BytesParse<U32>>();
        let (block_size, r) = r.read::<U32>();

        // Check that the number of hashed pages doesn't exceed the maximum
        {
            // All sections except for `drive_size` are parsed as an u32, so
            // they cannot overflow when adding together. Check the drive size
            // first, and if it doesn't overflow then check the sum.

            if drive_size > MAX_HASHED_PAGES.to_bytes() {
                return Err(Self::Error::InvalidHashedPagesCount {
                    // We can't do `drive_size.to_page_count()` here, as the cast from u64
                    // to u32 could fail.
                    hashed_pages: if drive_size.0.div_ceil(PAGE_SIZE as u64) >= u32::MAX as u64 {
                        Pages(u32::MAX)
                    } else {
                        drive_size.to_page_count()
                    },
                });
            }

            // The `drive_size` didn't overflow the maximum number of pages.
            // Now check that adding the other sections is still in-bounds.

            let hashed_pages = Pages(
                user_data_length
                    .to_page_count()
                    .0
                    .saturating_add(xvc_data_length.to_page_count().0)
                    .saturating_add(dynamic_header_length.to_page_count().0)
                    .saturating_add(drive_size.to_page_count().0),
            );

            if hashed_pages > MAX_HASHED_PAGES {
                return Err(Self::Error::InvalidHashedPagesCount { hashed_pages });
            }
        }

        let (ext_entries, r) = r.read::<[XvdExtEntry; 4]>();
        let (capabilities, r) = r.read::<[U16; 8]>();

        let (pe_catalog_hash, r) = r.array::<0x20>();
        let (embedded_xvd_pduid, r) = r.read::<Uuid>();
        let (_reserved13c, r) = r.array::<0x10>();
        let (key_material, r) = r.array::<0x20>();
        let (user_data_hash, r) = r.array::<0x20>();
        let (sandbox_id, r) = r.array::<0x10>();
        let (product_id, r) = r.read::<Uuid>();
        let (pduid, r) = r.read::<Uuid>();
        let (package_version, r) = r.read::<Version>();

        let (pe_catalog_caps, r) = r.read::<[U16; 0x10]>();
        let (pe_catalogs, r) = r.array::<0x80>();

        let (writeable_expiration_date, r) = r.read::<U32>();
        let (writeable_policy_flags, r) = r.read::<WriteablePolicyFlags>();

        let (persistent_local_storage_size, r) = r.read::<U32>();
        let (mutable_page_count, r) = r.read::<PagesParse<u8>>();

        let (_unknown271, r) = r.read::<u8>();
        let (_unknown272, r) = r.array::<0x10>();
        let (_reserved282, r) = r.array::<0xA>();

        let (sequence_number, r) = r.read::<I64>();
        let (required_system_version, r) = r.read::<Version>();
        let (odk_keyslot_id, r) = r.read::<U32>();
        let (_reservedd2a0, r) = r.advance::<Sum<typenum::U2048, typenum::U852>>();
        let (resilient_data_offset, r) = r.read::<U64>();
        let (resilient_data_length, r) = r.read::<U32>();

        Ok((
            Self {
                volume_flags,
                format_version,
                file_time_created,
                drive_size,
                vduid,
                uduid,
                top_hash_block_hash,
                original_xvc_data_hash,
                xvd_type,
                xvd_content_type,
                embedded_xvd_length,
                user_data_length,
                xvc_data_length,
                dynamic_header_length,
                block_size,
                ext_entries,
                capabilities,
                pe_catalog_hash,
                embedded_xvd_pduid,
                key_material,
                user_data_hash,
                sandbox_id,
                product_id,
                pduid,
                package_version,
                pe_catalog_caps,
                pe_catalogs,
                writeable_expiration_date,
                writeable_policy_flags,
                persistent_local_storage_size,
                mutable_page_count,
                sequence_number,
                required_system_version,
                odk_keyslot_id,
                resilient_data_offset,
                resilient_data_length,
            },
            r,
        ))
    }
}
