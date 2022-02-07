use super::error::GetOsRandomBytesError;
use crate::os::linux::getrandom;

/// Returns cryptographically secure random bytes with the specified `len`.
pub(crate) fn get_os_random_bytes_impl(len: u32) -> Result<Vec<u8>, GetOsRandomBytesError> {
    // Limits "chunk length" to 256 bytes.
    //
    // `man getrandom`:
    //
    // If the urandom source has been initialized, reads of up to 256
    // bytes will always return as many bytes as requested and will not
    // be interrupted by signals.  No such guarantees apply for larger
    // buffer sizes.  For example, if the call is interrupted by a
    // signal handler, it may return a partially filled buffer, or fail
    // with the error EINTR.
    const CHUNK_BYTES_LEN: usize = 256;

    let mut bytes = vec![0u8; len as usize];
    for chunk in bytes.chunks_mut(CHUNK_BYTES_LEN) {
        match getrandom(chunk) {
            Ok(len) => {
                if usize::try_from(len).unwrap() != chunk.len() {
                    return Err(
                        GetOsRandomBytesError::LinuxGetRandomCopiedNumberLessThanRequested,
                    );
                }
            }
            Err(errno) => return Err(GetOsRandomBytesError::LinuxGetRandom(errno)),
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::get_os_random_bytes_impl;
    use crate::os::linux::libc;
    use crate::os::LibcErrno;
    use crate::random::GetOsRandomBytesError;

    #[test]
    #[should_panic]
    fn mock_test_get_os_random_bytes_impl() {
        // success
        {
            let ctx = libc::getrandom_context();
            ctx.expect().return_const(16_isize);
            assert_eq!(get_os_random_bytes_impl(16).unwrap(), vec![0u8; 16]);
        }

        // getrandom returns -1
        {
            let ctx1 = libc::getrandom_context();
            ctx1.expect().return_const(-1_isize);
            let ctx2 = libc::__errno_location_context();
            let mut errno: LibcErrno = 35;
            ctx2.expect()
                .returning(move || (&mut errno) as *mut LibcErrno);
            assert_eq!(
                get_os_random_bytes_impl(16).unwrap_err(),
                GetOsRandomBytesError::LinuxGetRandom(35)
            );
        }

        // getrandom returns a number less than requested
        {
            let ctx = libc::getrandom_context();
            ctx.expect().return_const(8_isize);
            assert_eq!(
                get_os_random_bytes_impl(16).unwrap_err(),
                GetOsRandomBytesError::LinuxGetRandomCopiedNumberLessThanRequested
            );
        }

        // panic: getrandom returns < -1
        // This situation should never happen
        {
            let ctx = libc::getrandom_context();
            ctx.expect().return_const(-6_isize);
            assert_eq!(get_os_random_bytes_impl(16).unwrap(), vec![0u8; 16]);
        }
    }
}
