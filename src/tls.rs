#[cfg(all(esp_idf_esp_tls_psk_verification, feature = "alloc"))]
use core::convert::TryFrom;

use core::fmt::Debug;
use std::ffi::{c_char, CStr};

#[cfg(all(esp_idf_esp_tls_psk_verification, feature = "alloc"))]
use crate::sys::EspError;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Psk<'a> {
    pub key: &'a [u8],
    pub hint: &'a str,
}

impl Debug for Psk<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Psk")
            .field("hint", &self.hint)
            .finish_non_exhaustive()
    }
}

/// Helper for holding PSK data for lately initialized TLS connections.
///
/// It could be easily converted from the public `Psk` configuration and holds the `psk_hint_key_t`
/// along with its (string) data as this data typically needs to be around after initializing a TLS
/// client until it has been started.
#[cfg(all(esp_idf_esp_tls_psk_verification, feature = "alloc"))]
pub(crate) struct TlsPsk {
    pub(crate) psk: alloc::boxed::Box<crate::hal::sys::psk_hint_key_t>,
    pub(crate) _cstrs: crate::private::cstr::RawCstrs,
}
/// Dummy for maintaining the same internal interface whether TLS PSK support is enabled or not.
#[cfg(not(all(esp_idf_esp_tls_psk_verification, feature = "alloc")))]
#[allow(dead_code)]
pub(crate) struct TlsPsk {}

#[cfg(all(esp_idf_esp_tls_psk_verification, feature = "alloc"))]
impl Debug for TlsPsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("TlsPsk")
            .field("psk", &self.psk)
            .finish_non_exhaustive()
    }
}

#[cfg(all(esp_idf_esp_tls_psk_verification, feature = "alloc"))]
impl<'a> TryFrom<&'a Psk<'a>> for TlsPsk {
    type Error = EspError;

    fn try_from(conf: &Psk) -> Result<Self, EspError> {
        let mut cstrs = crate::private::cstr::RawCstrs::new();
        let psk = alloc::boxed::Box::new(crate::hal::sys::psk_hint_key_t {
            key: conf.key.as_ptr(),
            key_size: conf.key.len(),
            hint: cstrs.as_ptr(conf.hint)?,
        });

        Ok(TlsPsk { psk, _cstrs: cstrs })
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct X509<'a>(&'a [u8]);

impl<'a> X509<'a> {
    pub fn pem(cstr: &'a CStr) -> Self {
        Self(cstr.to_bytes_with_nul())
    }

    pub const fn pem_until_nul(bytes: &'a [u8]) -> Self {
        // TODO: replace with `CStr::from_bytes_until_nul` when stabilized
        let mut nul_pos = 0;
        while nul_pos < bytes.len() {
            if bytes[nul_pos] == 0 {
                // TODO: replace with `<[u8]>::split_at(nul_pos + 1)` when const stabilized
                let slice = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), nul_pos + 1) };
                return Self(slice);
            }
            nul_pos += 1;
        }
        panic!("PEM certificates should end with a NIL (`\\0`) ASCII character.")
    }

    pub const fn der(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn data(&self) -> &[u8] {
        self.0
    }

    #[allow(unused)]
    pub(crate) fn as_esp_idf_raw_ptr(&self) -> *const c_char {
        self.data().as_ptr().cast()
    }

    #[allow(unused)]
    pub(crate) fn as_esp_idf_raw_len(&self) -> usize {
        self.data().len()
    }
}

impl Debug for X509<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("X509").finish_non_exhaustive()
    }
}
