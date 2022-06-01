// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Returns a subslice with the leading zero bytes removed.
///
/// If the slice has leading zeros, returns the subslice after the leading zero bytes.
/// If the slice doesn't have leading zeros, simply returns the original slice.
/// If the slice contains only zeros, returns an empty slice.
///
/// # Examples
///
/// ```text
/// assert_eq!(strip_leading_zeros(&[0, 0, 1, 2, 3]), &[1, 2, 3]);
/// assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
/// assert_eq!(strip_leading_zeros(&[0, 0, 0, 0, 0]), "".as_bytes());
/// ```
pub(crate) fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    if let Some(index) = bytes.iter().position(|&x| x != 0) {
        &bytes[index..]
    } else {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_leading_zeros() {
        let data: &[(&[u8], &[u8])] = &[
            // (&[], &[]),
            (&[0][..], &[]),
            (&[0, 0][..], &[]),
            (&[0, 0, 1][..], &[1][..]),
            (&[1][..], &[1][..]),
            (&[0, 1][..], &[1][..]),
            (&[0, 1, 1][..], &[1, 1][..]),
            (&[0, 0, 1, 1][..], &[1, 1][..]),
            (&[0, 0, 1, 1, 0][..], &[1, 1, 0][..]),
        ];
        for (bytes, remaining) in data {
            assert_eq!(strip_leading_zeros(bytes), *remaining);
        }
    }
}
