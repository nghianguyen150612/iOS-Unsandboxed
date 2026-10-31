//! Checked directory enumeration shared by security-sensitive trust readers.

use std::collections::BTreeSet;
use std::io;

pub(crate) fn classify_readdir_result<T>(entry: Option<T>, error: i32) -> io::Result<Option<T>> {
    if entry.is_none() && error != 0 {
        Err(io::Error::from_raw_os_error(error))
    } else {
        Ok(entry)
    }
}

pub(crate) fn collect_entries<F>(mut next: F) -> io::Result<BTreeSet<Vec<u8>>>
where
    F: FnMut() -> io::Result<Option<Vec<u8>>>,
{
    let mut entries = BTreeSet::new();
    while let Some(entry) = next()? {
        entries.insert(entry);
    }
    Ok(entries)
}

pub(crate) unsafe fn read_directory(stream: *mut libc::DIR) -> io::Result<BTreeSet<Vec<u8>>> {
    collect_entries(|| {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream) };
        let name = if entry.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                    .to_bytes()
                    .to_vec(),
            )
        };
        classify_readdir_result(name, get_errno())
    })
}

fn set_errno(value: i32) {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = value;
    }
    #[cfg(target_vendor = "apple")]
    unsafe {
        *libc::__error() = value;
    }
}

fn get_errno() -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(target_vendor = "apple")]
    unsafe {
        *libc::__error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readdir_error_is_not_mistaken_for_end_of_directory() {
        let mut calls = 0;
        let result = collect_entries(|| {
            calls += 1;
            if calls == 1 {
                classify_readdir_result(Some(b"store.v1".to_vec()), 0)
            } else {
                classify_readdir_result::<Vec<u8>>(None, libc::EIO)
            }
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn null_readdir_result_with_zero_errno_is_end_of_directory() {
        assert!(classify_readdir_result::<Vec<u8>>(None, 0)
            .unwrap()
            .is_none());
    }
}
