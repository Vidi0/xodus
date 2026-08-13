//! Additional types for parsing with a [`BytesReader`](super::BytesReader).

use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt::{self, Debug, Display};

/// A version number that consists of major, minor, patch, and build components.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl Version {
    /// Creates a [`Version`] from a byte array.
    ///
    /// The input is expected as it appears in the XVD header, where the least
    /// significant version component comes first: `[build, patch, minor, major]`,
    /// and every component is stored as a little-endian `u16`.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            build: u16::from_le_bytes([bytes[0], bytes[1]]),
            patch: u16::from_le_bytes([bytes[2], bytes[3]]),
            minor: u16::from_le_bytes([bytes[4], bytes[5]]),
            major: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.build.cmp(&other.build))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use the Display implementation as the Debug one
        write!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_cmp() {
        let lower = Version {
            major: 1,
            minor: 26,
            patch: 3005,
            build: 0,
        };
        let higher = Version {
            major: 1,
            minor: 26,
            patch: 3101,
            build: 0,
        };
        let other_high = Version {
            major: 1,
            minor: 26,
            patch: 3101,
            build: 0,
        };
        let other_high2 = Version {
            major: 2,
            minor: 26,
            patch: 3101,
            build: 0,
        };

        assert!(lower < higher);
        assert!(higher > lower);
        assert!(higher == other_high);
        assert!(other_high2 > other_high);
    }
}
