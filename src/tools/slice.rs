// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Iterates `slice` over all contiguous windows of length `window_size`,
/// and calls a closure `f` on each window, starting at the end of the slice.
///
/// - The windows overlap.
/// - Will panic if `slice` is shorter than `size`.
pub(crate) fn rwindows_mut_each<T>(
    slice: &mut [T],
    window_size: usize,
    mut f: impl FnMut(&mut [T]),
) {
    assert!(
        window_size <= slice.len(),
        "the window is larger than the slice"
    );

    let mut start = slice.len() - window_size;
    let mut end = start + window_size;
    loop {
        f(&mut slice[start..end]);
        if start == 0 {
            break;
        }
        start -= 1;
        end -= 1;
    }
}
