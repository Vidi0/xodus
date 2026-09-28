## Integrity

MSIXVC packages are served from Microsoft's CDN over the insecure HTTP protocol
because they contain their own integrity information. This information can be
used to ensure that the package has not been tampered with and that it comes
from a trusted source. This is checked via the hash tree and the header's RSA
signature, respectively.

### Hash Tree

Following the `Mutable Data` section in the MSIXVC package is the `Hash Tree`
section. This section contains a Merkle hash tree which can be used to verify
the integrity of all the remaining pages of the package. Each page of the hash
tree contains up to 170 24-byte entries, which are truncated SHA-256
hashes.[^1] Because 4096 is not a multiple of 24, the final 16 bytes of each
page are filled with zeroes. Each hash is calculated from a page of data
(4096 bytes).

[^1]:
    Level 0 hash entries that point to encrypted data are also 24 bytes long,
    but the SHA-256 hash is truncated further to 20 bytes in order to make room
    for the 4-byte `data unit`. See [encryption](./encryption.md).

The hash tree is divided into multiple levels. Level 0 contains the hashes of
the actual data pages, and each subsequent level contains the hashes of the
pages from the level below it. The topmost level of the tree fits into a single
page, and its hash is stored directly in the header. Thus, a chain of trust is
established: the hash stored in the header verifies the topmost level of the
tree, and each level verifies the one below it. Since Level 0 verifies the
actual data, everything following the hash tree is ultimately verified by a
single hash in the header.

Entries from different levels of the hash tree are never stored on the same
page. Instead, the last page of each level may be padded with zero bytes. The
levels are stored in order, starting with the topmost level and ending with
level 0. MSIXVC packages may have up to 4 hash tree levels, but they could have
fewer because additional levels are only created if a level spans more than one
page.

The size of the hash tree section is not stored in the header. Instead, its
size is calculated based on the number of pages it covers. Each page of the
hash tree covers 170 pages. Therefore, each level occupies exactly `⌈N / 170⌉`
pages, where `N` is the number of pages of either the actual data or the level
below it. The total number of pages occupied by the hash tree is the sum of
every level's size.[^2]

[^2]:
    This total can be approximated as `⌈D / (170 - 1)⌉` pages, where `D` is the
    number of data pages. This approximation is not exact because each level is
    rounded up to a whole page, whereas the approximation uses fractional
    pages.

For example, the hash trees for a 100 GiB game and a 15 GiB game occupy the
following number of pages:

|            | 100 GiB    | 15 GiB    |
| ---------- | ---------- | --------- |
| Data pages | 26,214,400 | 3,932,160 |
| Level 0    | 154,203    | 23,131    |
| Level 1    | 908        | 137       |
| Level 2    | 6          | 1         |
| Level 3    | 1          | -         |
| Total      | 155,118    | 23,269    |

### Header Signature

Before the header, every MSIXVC package starts with a 512-byte RSA signature,
which signs the header. Because the header contains the hash of the topmost
tree level, verifying the header also checks the rest of the package. The only
sections that aren't verified are the `Embedded XVD` and the `Mutable Data`
sections.

The header is signed with Microsoft's private key.
