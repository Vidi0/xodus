use crate::math::gf_mul_x;
use crate::models::xvd::{PAGE_SIZE, XvcRegionId};

use std::cmp::Ordering;
use std::io::{self, Read, Seek, SeekFrom};
use std::iter;
use std::range::Range;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128Dec, Aes128Enc};
use thiserror::Error;
use uuid::Uuid;

/// A [`TweakGenerator`] stores all common fields needed to generate every [`Tweak`]
/// for an XVC region.
#[derive(Clone, Copy, Debug)]
pub struct TweakGenerator {
    region_id: [u8; 4],
    vduid: [u8; 8],
}

impl TweakGenerator {
    pub fn new(region_id: XvcRegionId, vduid: Uuid) -> Self {
        Self {
            region_id: region_id.to_le_bytes(),
            vduid: vduid.to_bytes_le()[..8].try_into().unwrap(),
        }
    }

    pub fn with_data_unit(self, data_unit: u32) -> Tweak {
        let mut buf = [0u8; 16];

        buf[0..4].copy_from_slice(&data_unit.to_le_bytes());
        buf[4..8].copy_from_slice(&self.region_id);
        buf[8..16].copy_from_slice(&self.vduid);

        Tweak(buf)
    }
}

/// A [`Tweak`] is the per-page tweak input, derived from a [`TweakGenerator`] by adding
/// a unique `data_unit` via [`TweakGenerator::with_data_unit`].
#[derive(Clone, Copy, Debug)]
pub struct Tweak([u8; 16]);

impl Tweak {
    fn encrypt(self, tweak_cipher: &Aes128Enc) -> u128 {
        let mut block = aes::Block::from(self.0);
        tweak_cipher.encrypt_block(&mut block);
        u128::from_le_bytes(block.0)
    }
}

/// A [`RegionDecryptor`] decrypts pages within an XVC region using AES-XTS.
///
/// It is generic over `Units` (bounded by `AsRef<[u32]>`) so callers can supply
/// data units as borrowed or owned.
#[derive(Clone, Debug)]
pub struct RegionDecryptor<Units> {
    tweak: TweakGenerator,

    tweak_cipher: Aes128Enc,
    data_cipher: Aes128Dec,

    /// If integrity is enabled, it must contain one entry per page in the region.
    /// If integrity is disabled, `page_in_section` is used as the data unit instead, so this
    /// field must be left empty (`&[]`).
    data_units: Units,
}

impl<Units> RegionDecryptor<Units>
where
    Units: AsRef<[u32]>,
{
    pub fn new(region_id: XvcRegionId, vduid: Uuid, full_key: [u8; 32], data_units: Units) -> Self {
        Self {
            tweak: TweakGenerator::new(region_id, vduid),
            tweak_cipher: Aes128Enc::new(full_key[..16].try_into().unwrap()),
            data_cipher: Aes128Dec::new(full_key[16..].try_into().unwrap()),
            data_units,
        }
    }

    /// Decrypts `page` in place, using the corresponding tweak for `page_in_region`.
    ///
    /// The caller must ensure that `page_in_region` is in-bounds for this region.
    /// Else, this function will place invalid data into `page`.
    pub fn decrypt_at(&self, page_in_region: usize, page: &mut [u8; PAGE_SIZE]) {
        let tweak = self.tweak.with_data_unit(
            // Get the data unit that corresponds to this page, or `page_in_region` if missing.
            self.data_units
                .as_ref()
                .get(page_in_region)
                .copied()
                .unwrap_or(page_in_region as u32),
        );

        decrypt_page_xts(page, tweak, &self.tweak_cipher, &self.data_cipher);
    }
}

#[derive(Clone, Debug)]
pub struct Region<Units> {
    pages: Range<u64>,
    decryptor: Option<RegionDecryptor<Units>>,
}

#[derive(Debug, Error)]
pub enum NewRegionError {
    #[error("region page range is inverted: {0:?}")]
    InvalidPageRange(Range<u64>),

    #[error("expected {expected} data units to match page count, found {found}")]
    InvalidDataUnitCount { expected: u64, found: u64 },
}

impl<Units> Region<Units>
where
    Units: AsRef<[u32]>,
{
    pub fn new(
        pages: Range<u64>,
        decryptor: Option<RegionDecryptor<Units>>,
    ) -> Result<Self, NewRegionError> {
        // Make sure the range makes sense.
        if pages.end < pages.start {
            return Err(NewRegionError::InvalidPageRange(pages));
        }

        let num_pages = pages.end - pages.start;

        // If the decryptor provides data units, make sure there is one data unit for each page.
        if let Some(dec) = &decryptor
            && let data_units @ 1.. = dec.data_units.as_ref().len() as u64
            && data_units != num_pages
        {
            return Err(NewRegionError::InvalidDataUnitCount {
                expected: num_pages,
                found: data_units,
            });
        }

        Ok(Self { pages, decryptor })
    }
}

pub struct DecryptorReader<R, Units> {
    /// The underlying reader, which spans the whole file.
    inner: R,

    /// The current offset that this reader is positioned at (relative to the start
    /// of the inner reader).
    read_offset: usize,

    /// List of each region: the indices of the pages it spans and its decryptor (if encrypted).
    regions: Vec<Region<Units>>,

    /// Page cache, needed for decryption because pages must be decrypted as a whole.
    /// It is stored inside a `Box` in order to make the [`DecryptorReader`] struct smaller.
    page: Box<[u8; PAGE_SIZE]>,
}

#[derive(Debug, Error)]
pub enum NewDecryptorReaderError<Units> {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("all regions must be consecutive")]
    NonConsecutiveRegions(Vec<Region<Units>>),
}

impl<R, Units> DecryptorReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    pub fn new(
        inner: R,
        regions: Vec<Region<Units>>,
    ) -> Result<Self, NewDecryptorReaderError<Units>> {
        // All regions must be consecutive. The first one must start at page 0.
        if regions
            .iter()
            .try_fold(0, |acc, r| (acc == r.pages.start).then_some(r.pages.end))
            .is_none()
        {
            return Err(NewDecryptorReaderError::NonConsecutiveRegions(regions));
        };

        let mut reader = Self {
            inner,
            read_offset: 0,
            regions,
            page: Box::new([0u8; PAGE_SIZE]),
        };

        // Fill the buffer with the first page.
        reader.next_page()?;

        Ok(reader)
    }

    #[inline]
    fn reader_len(&self) -> u64 {
        self.regions
            .last()
            .map(|r| r.pages.end * PAGE_SIZE as u64)
            .unwrap_or_default()
    }

    #[inline]
    fn is_finished(&self) -> bool {
        self.read_offset as u64 >= self.reader_len()
    }

    #[inline]
    fn current_page(&self) -> usize {
        self.read_offset / PAGE_SIZE
    }

    fn next_page(&mut self) -> io::Result<()> {
        assert!(self.read_offset.is_multiple_of(PAGE_SIZE));

        // If there are no remaining pages in this region, return without
        // filling the buffer.
        if self.is_finished() {
            return Ok(());
        }

        // Read the new page.
        self.inner.read_exact(&mut *self.page)?;

        // Decrypt the new page.
        let current_page = self.current_page() as u64;
        let current_region = &self.regions[self
            .regions
            .binary_search_by(|r| match current_page {
                p if p < r.pages.start => Ordering::Greater,
                p if p >= r.pages.end => Ordering::Less,
                _ => Ordering::Equal,
            })
            .expect("current page must be in some region")];

        if let Some(decryptor) = &current_region.decryptor {
            let page_in_region = (current_page - current_region.pages.start) as usize;
            decryptor.decrypt_at(page_in_region, &mut self.page);
        }

        Ok(())
    }

    fn consume(&mut self, bytes: usize) -> io::Result<()> {
        let current_off = self.read_offset;
        let current_page = current_off / PAGE_SIZE;

        let next_off = current_off + bytes;
        let next_page = next_off / PAGE_SIZE;

        assert!(bytes <= PAGE_SIZE);
        assert!(next_off <= (current_page + 1) * PAGE_SIZE);

        // Advance the read offset
        self.read_offset = next_off;

        // Refill the buffer if it has been emptied.
        if next_page > current_page {
            self.next_page()?;
        }

        Ok(())
    }

    fn remaining_page(&self) -> &[u8] {
        if self.is_finished() {
            return &[];
        }

        let page_offset = self.read_offset % PAGE_SIZE;
        &self.page[page_offset..]
    }
}

impl<R, Units> Read for DecryptorReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let remaining_page = self.remaining_page();
        let bytes = std::cmp::min(buf.len(), remaining_page.len());

        buf[..bytes].copy_from_slice(&remaining_page[..bytes]);
        self.consume(bytes)?;

        Ok(bytes)
    }
}

impl<R, Units> Seek for DecryptorReader<R, Units>
where
    R: Read + Seek,
    Units: AsRef<[u32]>,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let old_pos = self.read_offset as u64;
        let new_pos = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.reader_len().checked_add_signed(n),
            SeekFrom::Current(n) => old_pos.checked_add_signed(n),
        };

        let new_pos = match new_pos {
            Some(pos) if pos <= self.reader_len() => pos,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                ));
            }
        };

        let old_page = old_pos / PAGE_SIZE as u64;
        let new_page = new_pos / PAGE_SIZE as u64;

        // If the page hasn't changed, update the `read_offset` pointer and
        // return without modifying the buffer.
        if old_page == new_page {
            self.read_offset = new_pos as usize;
            return Ok(new_pos);
        }

        // Seek to the start of the new page, decrypt it, and then set `read_offset`
        // to the correct value.

        // It is guaranteed by the constructor of `DecryptorReader` that the first region
        // starts at page number 0, so the start of the new page is absolute to the start
        // of the inner reader.
        if let Some(region) = self.regions.first() {
            assert!(region.pages.start == 0);
        }

        let start_new_page = new_page * PAGE_SIZE as u64;

        // If the page is the next one, seeking can be avoided as the inner reader is always
        // positioned at the start of the next page.
        if new_page != old_page + 1 {
            self.inner.seek(SeekFrom::Start(start_new_page))?;
        }

        self.read_offset = start_new_page as usize;
        self.next_page()?;
        self.read_offset = new_pos as usize;

        Ok(new_pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.read_offset as u64)
    }
}

/// A [`RegionReader`] decrypts pages within an XVC region as the data is being read
/// from an underlying reader.
pub struct RegionReader<R, Units> {
    /// The section of the whole file that this region spans. It is measured in bytes,
    /// and both the start and the end must be multiples of [`PAGE_SIZE`].
    region: Range<u64>,

    /// The underlying reader, which usually spans the whole file. If it only spans
    /// this region, then `self.region.start` must equal `0`.
    inner: R,

    /// The current offset that this reader is positioned at (relative to the start
    /// of the region). It must be smaller than [`Self::region_len`], unless the reader
    /// has been fully consumed.
    read_offset: usize,

    /// Decryptor struct with the AES keys and data units, used to decrypt whole pages.
    decryptor: RegionDecryptor<Units>,

    /// Page cache, needed for decryption because pages must be decrypted as a whole.
    /// It is stored inside a `Box` in order to make the [`RegionReader`] struct smaller.
    page: Box<[u8; PAGE_SIZE]>,
}

impl<R, Units> RegionReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    /// Create a new [`RegionReader`] that decrypts data from this region on the fly.
    ///
    /// The provided reader must point to the start of the region, as this function
    /// will fill its internal buffer with the first page's contents.
    pub fn new(
        inner: R,
        region: Range<u64>,
        decryptor: RegionDecryptor<Units>,
    ) -> io::Result<Self> {
        assert!(region.end > region.start);
        assert!(region.start.is_multiple_of(PAGE_SIZE as u64));
        assert!(region.end.is_multiple_of(PAGE_SIZE as u64));

        // If the decryptor has data units, it must provide the right amount.
        if let len @ 1.. = decryptor.data_units.as_ref().len() as u64 {
            assert_eq!(len, (region.end - region.start) / PAGE_SIZE as u64);
        }

        let mut reader = Self {
            region,
            decryptor,
            inner,
            read_offset: 0,
            page: Box::new([0u8; PAGE_SIZE]),
        };

        // Fill the buffer with the first page.
        reader.next_page()?;

        Ok(reader)
    }

    #[inline]
    fn region_len(&self) -> u64 {
        self.region.end - self.region.start
    }

    #[inline]
    fn is_finished(&self) -> bool {
        self.read_offset as u64 >= self.region_len()
    }

    fn next_page(&mut self) -> io::Result<()> {
        assert!(self.read_offset.is_multiple_of(PAGE_SIZE));

        // If there are no remaining pages in this region, return without
        // filling the buffer.
        if self.is_finished() {
            return Ok(());
        }

        self.inner.read_exact(&mut *self.page)?;

        let page_in_region = self.read_offset / PAGE_SIZE;
        self.decryptor.decrypt_at(page_in_region, &mut self.page);

        Ok(())
    }

    fn consume(&mut self, bytes: usize) -> io::Result<()> {
        let current_off = self.read_offset;
        let current_page = current_off / PAGE_SIZE;

        let next_off = current_off + bytes;
        let next_page = next_off / PAGE_SIZE;

        assert!(bytes <= PAGE_SIZE);
        assert!(next_off <= (current_page + 1) * PAGE_SIZE);

        // Advance the read offset
        self.read_offset = next_off;

        // Refill the buffer if it has been emptied.
        if next_page > current_page {
            self.next_page()?;
        }

        Ok(())
    }

    fn remaining_page(&self) -> &[u8] {
        if self.is_finished() {
            return &[];
        }

        let page_offset = self.read_offset % PAGE_SIZE;
        &self.page[page_offset..]
    }
}

impl<R, Units> Read for RegionReader<R, Units>
where
    R: Read,
    Units: AsRef<[u32]>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let remaining_page = self.remaining_page();
        let bytes = std::cmp::min(buf.len(), remaining_page.len());

        buf[..bytes].copy_from_slice(&remaining_page[..bytes]);
        self.consume(bytes)?;

        Ok(bytes)
    }
}

impl<R, Units> Seek for RegionReader<R, Units>
where
    R: Read + Seek,
    Units: AsRef<[u32]>,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let old_pos = self.read_offset as u64;
        let Some(new_pos) = (match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.region_len().checked_add_signed(n),
            SeekFrom::Current(n) => old_pos.checked_add_signed(n),
        }) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            ));
        };

        let old_page = old_pos / PAGE_SIZE as u64;
        let new_page = new_pos / PAGE_SIZE as u64;

        // If the page hasn't changed, update the `read_offset` pointer and
        // return without modifying the buffer.
        if old_page == new_page {
            self.read_offset = new_pos as usize;
            return Ok(new_pos);
        }

        // Seek to the start of the new page, decrypt it, and then set `read_offset`
        // to the correct value.

        let start_new_page = new_page * PAGE_SIZE as u64;
        let absolute_start_new_page = start_new_page + self.region.start;
        self.inner.seek(SeekFrom::Start(absolute_start_new_page))?;

        self.read_offset = start_new_page as usize;
        self.next_page()?;
        self.read_offset = new_pos as usize;

        Ok(new_pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.read_offset as u64)
    }
}

pub struct SectionReader<'t, R> {
    inner: R,
    section_offset: u64,
    section_length: u64,

    tweak: TweakGenerator,

    tweak_cipher: Aes128Enc,
    data_cipher: Aes128Dec,

    // If integrity is enabled, this must contain one entry per page in the section.
    // If integrity is disabled, use page_in_section as the data unit instead.
    data_units: Option<&'t [u32]>,

    // simplest useful cache
    cached_page_index: Option<u64>,
    cached_page_plaintext: [u8; PAGE_SIZE],
}

impl<'t, R: Read + Seek> SectionReader<'t, R> {
    pub fn new(
        inner: R,
        section_offset: u64,
        section_length: u64,
        header_id: XvcRegionId,
        vduid: Uuid,
        full_key: [u8; 32],
        data_units: Option<&'t [u32]>,
    ) -> Self {
        let mut tweak_key = [0u8; 16];
        let mut data_key = [0u8; 16];
        tweak_key.copy_from_slice(&full_key[..16]);
        data_key.copy_from_slice(&full_key[16..]);

        Self {
            inner,
            section_offset,
            section_length,
            tweak: TweakGenerator::new(header_id, vduid),
            tweak_cipher: Aes128Enc::new((&tweak_key).into()),
            data_cipher: Aes128Dec::new((&data_key).into()),
            data_units,
            cached_page_index: None,
            cached_page_plaintext: [0u8; PAGE_SIZE],
        }
    }

    pub fn read_at(&mut self, offset_in_section: u64, mut out: &mut [u8]) -> io::Result<()> {
        let end = offset_in_section
            .checked_add(out.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;

        if end > self.section_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read exceeds section length",
            ));
        }

        let mut cur_off = offset_in_section;

        while !out.is_empty() {
            let page_in_section = cur_off / PAGE_SIZE as u64;
            let in_page = (cur_off % PAGE_SIZE as u64) as usize;
            let copy_len = std::cmp::min(out.len(), PAGE_SIZE - in_page);

            self.ensure_page_decrypted(page_in_section)?;
            out[..copy_len]
                .copy_from_slice(&self.cached_page_plaintext[in_page..in_page + copy_len]);

            cur_off += copy_len as u64;
            out = &mut out[copy_len..];
        }

        Ok(())
    }

    fn ensure_page_decrypted(&mut self, page_in_section: u64) -> io::Result<()> {
        if self.cached_page_index == Some(page_in_section) {
            return Ok(());
        }

        let file_offset = self
            .section_offset
            .checked_add(page_in_section * PAGE_SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow"))?;

        let tweak = self.tweak.with_data_unit(match &self.data_units {
            Some(units) => *units
                .get(page_in_section as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing data unit"))?,
            None => page_in_section as u32,
        });

        let mut page = [0u8; PAGE_SIZE];
        self.inner.seek(SeekFrom::Start(file_offset))?;
        self.inner.read_exact(&mut page)?;

        decrypt_page_xts(&mut page, tweak, &self.tweak_cipher, &self.data_cipher);

        self.cached_page_plaintext = page;
        self.cached_page_index = Some(page_in_section);
        Ok(())
    }
}

/// Decrypts a page using XTS-AES (IEEE 1619-2007).
///
/// XTS-AES uses two keys: a tweak key to derive a per-page tweak, and a data key
/// to decrypt the data. Each 16-byte block is decrypted as `P = AES_dec(C ⊕ T) ⊕ T`,
/// where `T` is the AES-encrypted tweak, advanced by one GF(2¹²⁸) multiplication per block.
pub fn decrypt_page_xts(
    page: &mut [u8; PAGE_SIZE],
    tweak: Tweak,
    tweak_cipher: &Aes128Enc,
    data_cipher: &Aes128Dec,
) {
    transform_page_xts(page, tweak, tweak_cipher, |block| {
        data_cipher.decrypt_block(block);
    });
}

/// Encrypts a page using XTS-AES (IEEE 1619-2007).
///
/// XTS-AES uses two keys: a tweak key to derive a per-page tweak, and a data key
/// to encrypt the data. Each 16-byte block is encrypted as `C = AES_enc(P ⊕ T) ⊕ T`,
/// where `T` is the AES-encrypted tweak, advanced by one GF(2¹²⁸) multiplication per block.
#[expect(dead_code)]
pub fn encrypt_page_xts(
    page: &mut [u8; PAGE_SIZE],
    tweak: Tweak,
    tweak_cipher: &Aes128Enc,
    data_cipher: &Aes128Enc,
) {
    transform_page_xts(page, tweak, tweak_cipher, |block| {
        data_cipher.encrypt_block(block);
    });
}

/// Transforms a page using XTS-AES (IEEE 1619-2007).
///
/// Each 16-byte block is transformed as `out = transform(in ⊕ T) ⊕ T`, where `T` is the
/// AES-encrypted tweak, advanced by one GF(2¹²⁸) multiplication per block.
///
/// The `transform` function is called with each block after the tweak is applied, and should
/// perform either AES encryption or decryption.
#[inline]
fn transform_page_xts<F>(
    page: &mut [u8; PAGE_SIZE],
    tweak: Tweak,
    tweak_cipher: &Aes128Enc,
    transform: F,
) where
    F: Fn(&mut aes::Block),
{
    // XTS requires the data length to be a multiple of the block size (16 bytes).
    const { assert!(PAGE_SIZE.is_multiple_of(16)) };

    // Every tweak in the iterator is calculated by applying `gf_mul_x` to the previous one.
    let tweaks = iter::successors(Some(tweak.encrypt(tweak_cipher)), |t| Some(gf_mul_x(*t)));

    for (block, tweak) in page.as_chunks_mut::<16>().0.iter_mut().zip(tweaks) {
        let mut out = u128::from_le_bytes(*block);

        out ^= tweak;
        out = {
            let mut buf = aes::Block::from(out.to_le_bytes());
            transform(&mut buf);
            u128::from_le_bytes(buf.0)
        };
        out ^= tweak;

        *block = out.to_le_bytes();
    }
}
