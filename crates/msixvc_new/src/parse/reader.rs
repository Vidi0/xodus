//! This module implements methods for [`BytesReader`] for easier parsing.

use super::BytesReader;
use super::structs::Version;

use std::ops::Sub;

use chrono::DateTime;
use generic_array::{ArrayLength, ConstArrayLength, GenericArray, IntoArrayLength};
use typenum::{Const, Diff, U1, U2, U4, U8, U16};
use uuid::Uuid;

impl<'a, Size: ArrayLength> BytesReader<'a, Size> {
    /// Gets a reference to an array containing the first `N` bytes of the reader.
    pub fn array_ref<const N: usize>(
        self,
    ) -> (
        &'a [u8; N],
        BytesReader<'a, Diff<Size, ConstArrayLength<N>>>,
    )
    where
        Const<N>: IntoArrayLength,
        Size: Sub<ConstArrayLength<N>, Output: ArrayLength>,
    {
        let (head, reader) = self.advance();
        (AsRef::<[u8; N]>::as_ref(head), reader)
    }

    /// Gets an array containing the first `N` bytes of the reader.
    pub fn array<const N: usize>(
        self,
    ) -> ([u8; N], BytesReader<'a, Diff<Size, ConstArrayLength<N>>>)
    where
        Const<N>: IntoArrayLength,
        Size: Sub<ConstArrayLength<N>, Output: ArrayLength>,
    {
        let (head, reader) = self.advance();
        (*AsRef::<[u8; N]>::as_ref(head), reader)
    }
}

/// Converts a Microsoft FILETIME (number of 100ns intervals since 1601-01-01 UTC)
/// into a [`chrono::DateTime`]
const fn microsoft_filetime(filetime: i64) -> DateTime<chrono::Utc> {
    // FILETIME counts 100ns intervals since 1601-01-01 UTC.
    // Unix time counts nanoseconds since 1970-01-01 UTC.

    /// Number of 100 nanoseconds between FILETIME epoch and Unix time
    const FILETIME_TO_UNIX: i64 = 116_444_736_000_000_000;

    let unix_nanos = (filetime - FILETIME_TO_UNIX) * 100;
    DateTime::from_timestamp_nanos(unix_nanos)
}

macro_rules! reader_method {
    ($name:ident, $ret:ty, $n_ty:ty, $n:literal, |$bytes:ident| $body:expr) => {
        pub fn $name(self) -> ($ret, BytesReader<'a, Diff<Size, $n_ty>>)
        where
            Size: Sub<$n_ty, Output: ArrayLength>,
        {
            let ($bytes, reader) = self.array::<$n>();
            ($body, reader)
        }
    };
}

impl<'a, Size: ArrayLength> BytesReader<'a, Size> {
    reader_method!(u8_le, u8, U1, 1, |b| u8::from_le_bytes(b));
    reader_method!(i8_le, i8, U1, 1, |b| i8::from_le_bytes(b));
    reader_method!(u16_le, u16, U2, 2, |b| u16::from_le_bytes(b));
    reader_method!(i16_le, i16, U2, 2, |b| i16::from_le_bytes(b));
    reader_method!(u32_le, u32, U4, 4, |b| u32::from_le_bytes(b));
    reader_method!(i32_le, i32, U4, 4, |b| i32::from_le_bytes(b));
    reader_method!(u64_le, u64, U8, 8, |b| u64::from_le_bytes(b));
    reader_method!(i64_le, i64, U8, 8, |b| i64::from_le_bytes(b));

    reader_method!(version, Version, U8, 8, |b| Version::from_bytes(b));
    reader_method!(uuid, Uuid, U16, 16, |b| Uuid::from_bytes_le(b));
    reader_method!(filetime, DateTime<chrono::Utc>, U8, 8, |b| {
        microsoft_filetime(i64::from_le_bytes(b))
    });

    pub fn magic<N>(
        self,
        expected: &GenericArray<u8, N>,
    ) -> Result<BytesReader<'a, Diff<Size, N>>, &'a GenericArray<u8, N>>
    where
        N: ArrayLength,
        Size: Sub<N, Output: ArrayLength>,
    {
        let (magic, r) = self.advance::<N>();
        if magic == expected { Ok(r) } else { Err(magic) }
    }
}
