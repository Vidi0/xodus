//! Endian-aware integer parsers implementing [`BinaryParse`].
//!
//! [`Le<T>`] and [`Be<T>`] are zero-sized marker types that implement
//! [`BinaryParse`] for every multi-byte primitive integer, parsing `T` from
//! its little-endian or big-endian representation, respectively.

use super::{BinaryParse, BytesReader};

use generic_array::ConstArrayLength;
use typenum::U0;

use std::marker::PhantomData;

/// Marker type for parsing little-endian integers though [`BinaryParse`].
pub struct Le<T>(PhantomData<T>);

/// Marker type for parsing big-endian integers though [`BinaryParse`].
pub struct Be<T>(PhantomData<T>);

macro_rules! impl_le_be {
    ($ty:ty, $size:literal) => {
        impl BinaryParse for Le<$ty> {
            type Output = $ty;
            type Size = ConstArrayLength<$size>;

            #[inline]
            fn parse<'a>(r: BytesReader<'a, Self::Size>) -> ($ty, BytesReader<'a, U0>) {
                let (bytes, r) = r.array::<$size>();
                (<$ty>::from_le_bytes(bytes), r)
            }
        }

        impl BinaryParse for Be<$ty> {
            type Output = $ty;
            type Size = ConstArrayLength<$size>;

            #[inline]
            fn parse<'a>(r: BytesReader<'a, Self::Size>) -> ($ty, BytesReader<'a, U0>) {
                let (bytes, r) = r.array::<$size>();
                (<$ty>::from_be_bytes(bytes), r)
            }
        }
    };
}

impl_le_be!(u16, 2);
impl_le_be!(i16, 2);
impl_le_be!(u32, 4);
impl_le_be!(i32, 4);
impl_le_be!(u64, 8);
impl_le_be!(i64, 8);
impl_le_be!(u128, 16);
impl_le_be!(i128, 16);

/// Little-endian type aliases.
pub mod little_endian {
    use super::Le;

    pub type U16 = Le<u16>;
    pub type I16 = Le<i16>;
    pub type U32 = Le<u32>;
    pub type I32 = Le<i32>;
    pub type U64 = Le<u64>;
    pub type I64 = Le<i64>;
    pub type U128 = Le<u128>;
    pub type I128 = Le<i128>;
}

/// Big-endian type aliases.
pub mod big_endian {
    use super::Be;

    pub type U16 = Be<u16>;
    pub type I16 = Be<i16>;
    pub type U32 = Be<u32>;
    pub type I32 = Be<i32>;
    pub type U64 = Be<u64>;
    pub type I64 = Be<i64>;
    pub type U128 = Be<u128>;
    pub type I128 = Be<i128>;
}
