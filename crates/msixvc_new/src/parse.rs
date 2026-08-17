//! Provides methods for easily parsing binary structures into Rust structs.
//!
//! The key struct in this module is [`BytesReader`], which is a wrapper over a
//! byte array and stores its length as a generic parameter, thus preventing
//! out-of-bounds reads at compile time. See its docs for more information.
//!
//! Rather than using [`BytesReader`] directly, structures that can be parsed
//! from byte arrays should implement the [`BinaryParse`] or [`BinaryTryParse`]
//! traits, which provide the corresponding method for parsing from an array
//! for free. Furthermore, types implementing these traits can also be parsed
//! directly from a [`BytesReader`] using [`BytesReader::read`] or
//! [`BytesReader::try_read`].
//!
//! # See also
//! - [`BytesReader`]
//! - [`parse`]
//! - [`try_parse`]

pub mod byteorder;
pub mod structs;

use std::hint;
use std::mem;
use std::ops::{Mul, Sub};

use generic_array::sequence::{FallibleGenericSequence, GenericSequence, Split};
use generic_array::{ArrayLength, ConstArrayLength, GenericArray, IntoArrayLength};
use typenum::{Const, Diff, Prod, U0, U1};

const EMPTY_READER: BytesReader<'static, U0> = BytesReader(&GenericArray::from_array([]));

/// A reader that wraps a reference to a byte array and provides methods for parsing
/// fixed-length fields from it in order.
///
/// The fundamental operation on which every method of [`BytesReader`] is based
/// is [`BytesReader::advance`]. This function consumes the reader and splits
/// its underlying array in two at at the index `N`, which is provided at compile
/// time. It returns a reference to an array with a length of `N` and a new
/// [`BytesReader`], which wraps the remaining bytes. If there are not enough bytes
/// remaining in the reader to fill the array, an error occurs at compile time.
///
/// This reader is generic over a `Size` which implements [`generic_array::ArrayLength`],
/// so out-of-bounds reads are prevented at compile time. When stabilized, this reader's
/// `Size` could be stored using const generics instead of typenum's types.
///
/// # See also
/// - [`parse`]
/// - [`try_parse`]
pub struct BytesReader<'a, Size: ArrayLength>(&'a GenericArray<u8, Size>);

impl<'a, Size: ArrayLength> BytesReader<'a, Size> {
    /// Advances the reader by `N` bytes, returning a reference to the first `N`
    /// bytes as a reference to a [`GenericArray<u8, N>`].
    ///
    /// Returns a new updated reader. See [`BytesReader`] for more information.
    #[inline]
    pub fn advance<N>(self) -> (&'a GenericArray<u8, N>, BytesReader<'a, Diff<Size, N>>)
    where
        N: ArrayLength,
        Size: Sub<N, Output: ArrayLength>,
    {
        let (head, tail) = Split::split(self.0);
        (head, BytesReader(tail))
    }

    /// Consumes the reader, returning a reference to all remaining bytes.
    #[inline]
    pub fn remaining(self) -> (&'a GenericArray<u8, Size>, BytesReader<'a, U0>) {
        (self.0, EMPTY_READER)
    }

    /// Gets an array containing the first `N` bytes of the reader.
    #[inline]
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

    /// Checks that the next bytes of the reader match the ones in `magic`.
    #[inline]
    pub fn magic<const N: usize>(
        self,
        expected: &[u8; N],
    ) -> Result<BytesReader<'a, Diff<Size, ConstArrayLength<N>>>, [u8; N]>
    where
        Const<N>: IntoArrayLength,
        Size: Sub<ConstArrayLength<N>, Output: ArrayLength>,
    {
        let (magic, r) = self.array::<N>();
        if magic == *expected {
            Ok(r)
        } else {
            hint::cold_path();
            Err(magic)
        }
    }
}

/// Parses a byte array using a [`BytesReader`], ensuring that every byte in the
/// array is consumed.
///
/// The closure that parses the array must be provided at `f`. Inside the closure,
/// the caller is provided with a [`BytesReader`] which spans the entire array
/// to be parsed. [`BytesReader`]'s methods must be used to parse every field
/// from the array in order. These methods return new readers that only span the
/// remaining bytes of the array, thus guaranteeing at compile time that every
/// read is within bounds. To guarantee statically that every byte is always parsed,
/// an empty [`BytesReader`] must be returned, alongside the parsed data.
#[inline]
pub fn parse<'a, N, T>(
    array: &'a GenericArray<u8, N>,
    f: impl FnOnce(BytesReader<'a, N>) -> (T, BytesReader<'a, U0>),
) -> T
where
    N: ArrayLength,
{
    let reader = BytesReader(array);
    f(reader).0
}

/// Parses a byte array using a [`BytesReader`], where parsing may fail partway
/// through, ensuring that every byte is consumed on success.
///
/// See [`parse`] for more information.
#[inline]
pub fn try_parse<'a, N, T, E>(
    array: &'a GenericArray<u8, N>,
    f: impl FnOnce(BytesReader<'a, N>) -> Result<(T, BytesReader<'a, U0>), E>,
) -> Result<T, E>
where
    N: ArrayLength,
{
    let reader = BytesReader(array);
    f(reader).map(|(t, _reader)| t)
}

/// A trait implemented by types that describe how to parse a value from a byte
/// array.
pub trait BinaryParse {
    type Output;
    type Size: ArrayLength;

    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, BytesReader<'a, U0>);

    #[inline]
    fn from_array<'a>(array: &'a GenericArray<u8, Self::Size>) -> Self::Output {
        parse(array, Self::parse)
    }
}

/// A trait implemented by types that describe how to parse a value from a byte
/// array in a fallible way.
pub trait BinaryTryParse {
    type Output;
    type Size: ArrayLength;
    type Error;

    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, BytesReader<'a, U0>), Self::Error>;

    #[inline]
    fn try_from_array<'a>(
        array: &'a GenericArray<u8, Self::Size>,
    ) -> Result<Self::Output, Self::Error> {
        try_parse(array, Self::try_parse)
    }
}

impl<'a, Size: ArrayLength> BytesReader<'a, Size> {
    #[inline]
    pub fn read<T>(self) -> (T::Output, BytesReader<'a, Diff<Size, T::Size>>)
    where
        T: BinaryParse,
        Size: Sub<T::Size, Output: ArrayLength>,
    {
        let (head, reader) = self.advance::<T::Size>();
        (T::from_array(head), reader)
    }

    #[inline]
    pub fn try_read<T>(self) -> Result<(T::Output, BytesReader<'a, Diff<Size, T::Size>>), T::Error>
    where
        T: BinaryTryParse,
        Size: Sub<T::Size, Output: ArrayLength>,
    {
        let (head, reader) = self.advance::<T::Size>();
        T::try_from_array(head).map(|t| (t, reader))
    }
}

impl BinaryParse for () {
    type Output = ();
    type Size = U0;

    #[inline]
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, BytesReader<'a, U0>) {
        ((), r)
    }
}

impl BinaryParse for u8 {
    type Output = u8;
    type Size = U1;

    #[inline]
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, BytesReader<'a, U0>) {
        let (bytes, r) = r.array();
        (u8::from_ne_bytes(bytes), r)
    }
}

impl BinaryParse for i8 {
    type Output = i8;
    type Size = U1;

    #[inline]
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, BytesReader<'a, U0>) {
        let (bytes, r) = r.array();
        (i8::from_ne_bytes(bytes), r)
    }
}

/// Splits a reference to a `GenericArray<T, Size>` into a reference to `N`
/// chunks of length `M` each, where `Size = N * M`.
///
/// Usually, the [`Unflatten`](generic_array::sequence::Unflatten) trait should
/// be preferred, but it causes trouble when dividing by [`U0`].
#[inline]
fn unflatten_ref<'a, T, N, M>(
    array: &'a GenericArray<T, Prod<N, M>>,
) -> &'a GenericArray<GenericArray<T, M>, N>
where
    N: ArrayLength + Mul<M, Output: ArrayLength>,
    M: ArrayLength,
{
    // SAFETY: `GenericArray<T, Prod<N, M>>` and
    // `GenericArray<GenericArray<T, M>, N>` have identical size and layout.
    unsafe { mem::transmute(array) }
}

impl<T, N> BinaryParse for GenericArray<T, N>
where
    T: BinaryParse,
    N: ArrayLength + Mul<T::Size, Output: ArrayLength>,
{
    type Output = GenericArray<T::Output, N>;
    type Size = Prod<N, T::Size>;

    #[inline]
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, BytesReader<'a, U0>) {
        let (bytes, r) = r.remaining();
        let chunks = unflatten_ref::<u8, N, T::Size>(bytes);
        (GenericArray::generate(|i| T::from_array(&chunks[i])), r)
    }
}

impl<T, N> BinaryTryParse for GenericArray<T, N>
where
    T: BinaryTryParse,
    N: ArrayLength + Mul<T::Size, Output: ArrayLength>,
{
    type Output = GenericArray<T::Output, N>;
    type Size = Prod<N, T::Size>;
    type Error = T::Error;

    #[inline]
    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, BytesReader<'a, U0>), Self::Error> {
        let (bytes, r) = r.remaining();
        let chunks = unflatten_ref::<u8, N, T::Size>(bytes);
        let Ok(result) = GenericArray::try_generate(|i| T::try_from_array(&chunks[i]));
        result.map(|arr| (arr, r))
    }
}

impl<T, const N: usize> BinaryParse for [T; N]
where
    T: BinaryParse,
    Const<N>: IntoArrayLength,
    ConstArrayLength<N>: Mul<T::Size, Output: ArrayLength>,
{
    type Output = [T::Output; N];
    type Size = Prod<ConstArrayLength<N>, T::Size>;

    #[inline]
    fn parse<'a>(r: BytesReader<'a, Self::Size>) -> (Self::Output, BytesReader<'a, U0>) {
        let (array, r) = <GenericArray<T, ConstArrayLength<N>> as BinaryParse>::parse(r);
        (array.into_array(), r)
    }
}

impl<T, const N: usize> BinaryTryParse for [T; N]
where
    T: BinaryTryParse,
    Const<N>: IntoArrayLength,
    ConstArrayLength<N>: Mul<T::Size, Output: ArrayLength>,
{
    type Output = [T::Output; N];
    type Size = Prod<ConstArrayLength<N>, T::Size>;
    type Error = T::Error;

    #[inline]
    fn try_parse<'a>(
        r: BytesReader<'a, Self::Size>,
    ) -> Result<(Self::Output, BytesReader<'a, U0>), Self::Error> {
        <GenericArray<T, ConstArrayLength<N>> as BinaryTryParse>::try_parse(r)
            .map(|(array, r)| (array.into_array(), r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_implements_binary_parse() {
        const fn requires_binary_parse<T: BinaryParse>() {}

        // Zero-sized types should be able to implement `BinaryParse`, too.

        requires_binary_parse::<()>();
        requires_binary_parse::<[(); 0]>();
        requires_binary_parse::<[(); 1]>();

        requires_binary_parse::<u8>();
        requires_binary_parse::<[u8; 0]>();
        requires_binary_parse::<[u8; 1]>();
    }
}
