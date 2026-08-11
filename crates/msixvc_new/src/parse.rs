use std::ops::Sub;

use generic_array::{ArrayLength, GenericArray};
use typenum::{Diff, U0};

/// A reader that wraps a reference to a byte array and provides methods for parsing
/// fixed-length fields from it in order.
///
/// The fundamental operation on which every method of [`BytesReader`] is based
/// is [`BytesReader::array_ref`]. This function consumes the reader and splits
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
    /// Gets a reference to an array containing the first `N` bytes of the reader.
    ///
    /// Returns a new updated reader. See [`BytesReader`] for more information.
    pub fn array_ref<N>(self) -> (&'a GenericArray<u8, N>, BytesReader<'a, Diff<Size, N>>)
    where
        N: ArrayLength,
        Size: Sub<N, Output: ArrayLength>,
    {
        let (head, tail) = self.0.as_slice().split_at(N::USIZE);

        (
            GenericArray::from_slice(head),
            BytesReader(GenericArray::from_slice(tail)),
        )
    }

    /// Gets an array containing the first `N` bytes of the reader.
    ///
    /// Returns a new updated reader. See [`BytesReader`] for more information.
    pub fn array<N>(self) -> (GenericArray<u8, N>, BytesReader<'a, Diff<Size, N>>)
    where
        N: ArrayLength,
        Size: Sub<N, Output: ArrayLength>,
        GenericArray<u8, N>: Copy,
    {
        let (array, r) = self.array_ref();
        (*array, r)
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
