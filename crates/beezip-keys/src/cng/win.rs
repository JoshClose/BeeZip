//! CNG and CryptoAPI handles as RAII types, and the calls BeeZip makes with them. Every
//! function here is silent unless its `silent` argument is false: then a smart card's or TPM
//! key's PIN dialog may show, which only happens for a way in the user chose.

use std::{ffi::c_void, sync::Arc};

use beezip_core::{Error, ErrorKind, format::bhive::sign::Algorithm};
use windows::Win32::{
    Foundation::NTSTATUS,
    Security::{Cryptography::*, OBJECT_SECURITY_INFORMATION},
};
use windows_core::{BOOL, PCWSTR};
use zeroize::Zeroizing;

pub const NTE_BAD_FLAGS: u32 = 0x8009_0009;
pub const NTE_SILENT_CONTEXT: u32 = 0x8009_0022;
pub const NTE_NO_MORE_ITEMS: u32 = 0x8009_002A;

/// A CNG or CryptoAPI failure, with its HRESULT.
#[derive(Debug, Clone)]
pub struct WinError {
    pub code: u32,
    pub what: String,
}

impl WinError {
    pub fn new(e: &windows_core::Error, what: &str) -> Self {
        Self {
            code: e.code().0 as u32,
            what: format!(
                "{what}: {} (0x{:08X})",
                e.message().trim(),
                e.code().0 as u32
            ),
        }
    }

    /// The call needed a person (a PIN, a card) and was asked to be silent, or the device isn't
    /// there: a way in to offer, not a failure.
    pub fn needs_person(&self) -> bool {
        matches!(
            self.code,
            NTE_SILENT_CONTEXT
            // NTE_DEVICE_NOT_READY, SCARD_E_NO_SMARTCARD, SCARD_W_REMOVED_CARD,
            // SCARD_E_NO_SERVICE, SCARD_E_NO_READERS_AVAILABLE, SCARD_W_CANCELLED_BY_USER
            | 0x8009_0030 | 0x8010_000C | 0x8010_0069 | 0x8010_001D | 0x8010_002E | 0x8010_006E
        )
    }

    /// A closed PIN dialog is `Cancelled`, as a closed Windows Security dialog is
    /// (webauthn.rs), so an unlock asks for another way in; anything else is `Io`.
    pub fn into_error(self) -> Error {
        // HRESULT_FROM_WIN32(ERROR_CANCELLED), NTE_USER_CANCELLED, SCARD_W_CANCELLED_BY_USER
        let kind = if matches!(self.code, 0x8007_04C7 | 0x8009_0036 | 0x8010_006E) {
            ErrorKind::Cancelled
        } else {
            ErrorKind::Io
        };
        Error::new(kind, self.what)
    }
}

impl From<WinError> for Error {
    fn from(e: WinError) -> Self {
        e.into_error()
    }
}

pub type WinResult<T> = std::result::Result<T, WinError>;

fn check(r: windows_core::Result<()>, what: &str) -> WinResult<()> {
    r.map_err(|e| WinError::new(&e, what))
}

fn nt(s: NTSTATUS, what: &str) -> WinResult<()> {
    if s.0 >= 0 {
        Ok(())
    } else {
        Err(WinError {
            code: s.0 as u32,
            what: format!("{what}: NTSTATUS 0x{:08X}", s.0 as u32),
        })
    }
}

/// NUL-terminated UTF-16.
pub fn wz(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// NUL-terminated UTF-16 as bytes, for properties and parameter buffers.
pub fn wz_bytes(s: &str) -> Vec<u8> {
    wz(s).iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn utf16_to_string(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&u)
        .trim_end_matches('\0')
        .to_owned()
}

/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
unsafe fn from_pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: the caller promises a NUL-terminated string.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: the `n` units before the NUL are readable.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// Random bytes from the system.
pub fn random(out: &mut [u8]) -> WinResult<()> {
    // SAFETY: `out` is a valid buffer for its length.
    nt(
        unsafe { BCryptGenRandom(None, out, BCRYPT_USE_SYSTEM_PREFERRED_RNG) },
        "BCryptGenRandom",
    )
}

/// A BCrypt parameter list; the data it points to outlives it.
pub struct Params<'a> {
    bufs: Vec<BCryptBuffer>,
    desc: BCryptBufferDesc,
    _data: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Params<'a> {
    pub fn new(items: &[(u32, &'a [u8])]) -> Box<Self> {
        let bufs = items
            .iter()
            .map(|(t, b)| BCryptBuffer {
                cbBuffer: b.len() as u32,
                BufferType: *t,
                pvBuffer: b.as_ptr() as *mut c_void,
            })
            .collect();
        let mut p = Box::new(Self {
            bufs,
            desc: BCryptBufferDesc::default(),
            _data: std::marker::PhantomData,
        });
        p.desc = BCryptBufferDesc {
            ulVersion: BCRYPTBUFFER_VERSION,
            cBuffers: p.bufs.len() as u32,
            pBuffers: p.bufs.as_mut_ptr(),
        };
        p
    }

    pub fn desc(&self) -> *const BCryptBufferDesc {
        &self.desc
    }
}

/// A key storage provider, freed when dropped. Keys opened from it hold it: a key whose
/// provider handle is freed stops working.
pub struct Provider(NCRYPT_PROV_HANDLE);

// SAFETY: a provider handle may be used from any thread.
unsafe impl Send for Provider {}
// SAFETY: as above; nothing here changes it.
unsafe impl Sync for Provider {}

impl Provider {
    pub fn open(name: PCWSTR) -> WinResult<Arc<Self>> {
        let mut h = NCRYPT_PROV_HANDLE::default();
        // SAFETY: `h` receives a handle this type then owns.
        check(
            unsafe { NCryptOpenStorageProvider(&mut h, name, 0) },
            "NCryptOpenStorageProvider",
        )?;
        Ok(Arc::new(Self(h)))
    }

    /// The names of the persisted keys in this provider.
    pub fn key_names(&self) -> WinResult<Vec<String>> {
        // The TPM provider refuses the silent flag here; ask again without it, as nothing
        // in an enumeration shows UI.
        match self.key_names_with(NCRYPT_SILENT_FLAG) {
            Err(e) if e.code == NTE_BAD_FLAGS => self.key_names_with(NCRYPT_FLAGS(0)),
            r => r,
        }
    }

    fn key_names_with(&self, flags: NCRYPT_FLAGS) -> WinResult<Vec<String>> {
        let mut names = Vec::new();
        let mut state: *mut c_void = std::ptr::null_mut();
        let result = loop {
            let mut name: *mut NCryptKeyName = std::ptr::null_mut();
            // SAFETY: `name` and `state` are out-pointers the provider fills and we free.
            match unsafe { NCryptEnumKeys(self.0, PCWSTR::null(), &mut name, &mut state, flags) } {
                Ok(()) => {
                    // SAFETY: on success `name` points to a key name the provider allocated.
                    names.push(unsafe { from_pwstr((*name).pszName.0) });
                    // SAFETY: freed once, as the provider asks.
                    let _ = unsafe { NCryptFreeBuffer(name.cast()) };
                }
                Err(e) if e.code().0 as u32 == NTE_NO_MORE_ITEMS => break Ok(names),
                Err(e) => break Err(WinError::new(&e, "NCryptEnumKeys")),
            }
        };
        if !state.is_null() {
            // SAFETY: the enumeration state is freed once.
            let _ = unsafe { NCryptFreeBuffer(state) };
        }
        result
    }

    /// Opens the persisted key `name`, silently.
    pub fn open_key(self: &Arc<Self>, name: &str) -> WinResult<Key> {
        let w = wz(name);
        let mut h = NCRYPT_KEY_HANDLE::default();
        // SAFETY: `h` receives a handle the returned key owns.
        check(
            unsafe {
                NCryptOpenKey(
                    self.0,
                    &mut h,
                    PCWSTR(w.as_ptr()),
                    CERT_KEY_SPEC(0),
                    NCRYPT_SILENT_FLAG,
                )
            },
            "NCryptOpenKey",
        )?;
        Ok(Key {
            h,
            owned: true,
            _provider: Some(Arc::clone(self)),
        })
    }

    /// A new persisted key, not yet finalized: set its properties, then [`Key::finalize`].
    pub fn create_key(self: &Arc<Self>, algorithm: PCWSTR, name: Option<&str>) -> WinResult<Key> {
        let w = name.map(wz);
        let name = w.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
        let mut h = NCRYPT_KEY_HANDLE::default();
        // SAFETY: `h` receives a handle the returned key owns.
        check(
            unsafe {
                NCryptCreatePersistedKey(
                    self.0,
                    &mut h,
                    algorithm,
                    name,
                    CERT_KEY_SPEC(0),
                    NCRYPT_FLAGS(0),
                )
            },
            "NCryptCreatePersistedKey",
        )?;
        Ok(Key {
            h,
            owned: true,
            _provider: Some(Arc::clone(self)),
        })
    }

    /// A key from a blob (`BCRYPT_ECCPRIVATE_BLOB`, PKCS #8…), not persisted.
    #[cfg(test)]
    pub fn import(self: &Arc<Self>, blob_type: PCWSTR, blob: &[u8]) -> WinResult<Key> {
        let mut h = NCRYPT_KEY_HANDLE::default();
        // SAFETY: `h` receives a handle the returned key owns; `blob` is read only.
        check(
            unsafe {
                NCryptImportKey(
                    self.0,
                    None,
                    blob_type,
                    None,
                    &mut h,
                    blob,
                    NCRYPT_SILENT_FLAG,
                )
            },
            "NCryptImportKey",
        )?;
        Ok(Key {
            h,
            owned: true,
            _provider: Some(Arc::clone(self)),
        })
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

/// An NCrypt key: owned (freed when dropped), or borrowed from a certificate context that
/// keeps it.
pub struct Key {
    h: NCRYPT_KEY_HANDLE,
    owned: bool,
    /// The provider it was opened from, kept open as long as the key.
    _provider: Option<Arc<Provider>>,
}

// SAFETY: an NCrypt key handle may be used from any thread; BeeZip uses each from one at a
// time (signers hold theirs behind a mutex).
unsafe impl Send for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: the handle is owned and freed once.
            let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.h.0)) };
        }
    }
}

fn flags(silent: bool) -> NCRYPT_FLAGS {
    if silent {
        NCRYPT_SILENT_FLAG
    } else {
        NCRYPT_FLAGS(0)
    }
}

impl Key {
    /// Hands the handle to whoever takes it (a certificate context), so it isn't freed here.
    /// Its provider must stay open while the handle is used.
    #[cfg(test)]
    pub fn release(mut self) -> NCRYPT_KEY_HANDLE {
        self.owned = false;
        self.h
    }

    fn prop_of(h: NCRYPT_HANDLE, name: PCWSTR) -> WinResult<Vec<u8>> {
        let mut n = 0u32;
        // SAFETY: a size query, then a read into a buffer of that size.
        unsafe {
            check(
                NCryptGetProperty(h, name, None, &mut n, OBJECT_SECURITY_INFORMATION(0)),
                "NCryptGetProperty",
            )?;
            let mut v = vec![0; n as usize];
            check(
                NCryptGetProperty(
                    h,
                    name,
                    Some(&mut v),
                    &mut n,
                    OBJECT_SECURITY_INFORMATION(0),
                ),
                "NCryptGetProperty",
            )?;
            v.truncate(n as usize);
            Ok(v)
        }
    }

    pub fn prop(&self, name: PCWSTR) -> WinResult<Vec<u8>> {
        Self::prop_of(NCRYPT_HANDLE(self.h.0), name)
    }

    pub fn set_prop(&self, name: PCWSTR, value: &[u8]) -> WinResult<()> {
        // SAFETY: `value` is read only.
        check(
            unsafe { NCryptSetProperty(NCRYPT_HANDLE(self.h.0), name, value, NCRYPT_SILENT_FLAG) },
            "NCryptSetProperty",
        )
    }

    /// Makes `window` the parent of the dialogs its provider shows for this key (a smart card's
    /// or TPM key's PIN), through `NCRYPT_WINDOW_HANDLE_PROPERTY`, set silently. Without one
    /// they come up over the window in front.
    pub fn parent(&self, window: Option<isize>) -> WinResult<()> {
        let Some(window) = window else {
            return Ok(());
        };
        let hwnd = window.to_ne_bytes();
        let set = |flags| {
            // SAFETY: the property's value is the HWND itself, read only.
            check(
                unsafe {
                    NCryptSetProperty(
                        NCRYPT_HANDLE(self.h.0),
                        NCRYPT_WINDOW_HANDLE_PROPERTY,
                        &hwnd,
                        flags,
                    )
                },
                "NCryptSetProperty (the window)",
            )
        };
        // A provider that refuses the silent flag here is asked again without it: setting a
        // property shows nothing.
        match set(NCRYPT_SILENT_FLAG) {
            Err(e) if e.code == NTE_BAD_FLAGS => set(NCRYPT_FLAGS(0)),
            r => r,
        }
    }

    pub fn finalize(&self) -> WinResult<()> {
        // SAFETY: the key is ours and not yet finalized.
        check(
            unsafe { NCryptFinalizeKey(self.h, NCRYPT_SILENT_FLAG) },
            "NCryptFinalizeKey",
        )
    }

    /// `ECDH_P256`, `ECDSA_P256`, `RSA`…
    pub fn algorithm(&self) -> String {
        self.prop(NCRYPT_ALGORITHM_PROPERTY)
            .map(|v| utf16_to_string(&v))
            .unwrap_or_default()
    }

    /// The key's own provider. Borrowed: the key keeps it, and it must never be freed
    /// (freeing it frees the key's provider twice).
    fn provider(&self) -> WinResult<NCRYPT_PROV_HANDLE> {
        let v = self.prop(NCRYPT_PROVIDER_HANDLE_PROPERTY)?;
        let bytes: [u8; std::mem::size_of::<usize>()] = v
            .get(..std::mem::size_of::<usize>())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| WinError {
                code: 0,
                what: "a provider handle of the wrong size".into(),
            })?;
        Ok(NCRYPT_PROV_HANDLE(usize::from_ne_bytes(bytes)))
    }

    pub fn provider_name(&self) -> String {
        self.provider()
            .and_then(|p| Self::prop_of(NCRYPT_HANDLE(p.0), NCRYPT_NAME_PROPERTY))
            .map(|v| utf16_to_string(&v))
            .unwrap_or_default()
    }

    pub fn is_tpm(&self) -> bool {
        self.provider_name() == "Microsoft Platform Crypto Provider"
    }

    /// A TPM key with a PIN: using it silently would count a failed try against the TPM's
    /// lockout, so it is only used when the user chose it and Windows asks for the PIN.
    pub fn needs_pin(&self) -> bool {
        self.is_tpm()
            && self
                .prop(NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY)
                .is_ok_and(|v| v.first().is_some_and(|&b| b != 0))
    }

    pub fn export(&self, blob_type: PCWSTR) -> WinResult<Vec<u8>> {
        let mut n = 0u32;
        // SAFETY: a size query, then an export into a buffer of that size.
        unsafe {
            check(
                NCryptExportKey(
                    self.h,
                    None,
                    blob_type,
                    None,
                    None,
                    &mut n,
                    NCRYPT_SILENT_FLAG,
                ),
                "NCryptExportKey",
            )?;
            let mut v = vec![0; n as usize];
            check(
                NCryptExportKey(
                    self.h,
                    None,
                    blob_type,
                    None,
                    Some(&mut v),
                    &mut n,
                    NCRYPT_SILENT_FLAG,
                ),
                "NCryptExportKey",
            )?;
            v.truncate(n as usize);
            Ok(v)
        }
    }

    /// RSA-OAEP with SHA-256 and no label, which the TPM requires (bhive.md §12.5).
    pub fn decrypt_oaep(&self, ct: &[u8], silent: bool) -> WinResult<Zeroizing<Vec<u8>>> {
        let pad = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        };
        let pad = Some(&pad as *const _ as *const c_void);
        let f = NCRYPT_PAD_OAEP_FLAG | flags(silent);
        let mut n = 0u32;
        // SAFETY: `ct` and the padding info are read only; a size query, then a decryption
        // into a buffer of that size.
        unsafe {
            check(
                NCryptDecrypt(self.h, Some(ct), pad, None, &mut n, f),
                "NCryptDecrypt",
            )?;
            let mut out = Zeroizing::new(vec![0; n as usize]);
            check(
                NCryptDecrypt(self.h, Some(ct), pad, Some(&mut out), &mut n, f),
                "NCryptDecrypt",
            )?;
            out.truncate(n as usize);
            Ok(out)
        }
    }

    /// ECDH with `peer` (an uncompressed point) inside the key's provider, and `PRK =
    /// HMAC-SHA256(context, Z)` through `BCRYPT_KDF_HMAC`, the context as `KDF_HMAC_KEY` (never
    /// in the prepend, and never `BCRYPT_KDF_HKDF`, which is broken). Z never leaves the key's
    /// provider.
    pub fn ecdh_prk(
        &self,
        peer: &[u8],
        context: &[u8; 32],
        silent: bool,
    ) -> WinResult<Zeroizing<[u8; 32]>> {
        let half = (peer.len().saturating_sub(1)) / 2;
        let magic = match half {
            32 => BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            48 => BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            _ => {
                return Err(WinError {
                    code: 0,
                    what: "an EC point of the wrong size".into(),
                });
            }
        };
        let mut blob = Vec::with_capacity(8 + 2 * half);
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&(half as u32).to_le_bytes());
        blob.extend_from_slice(&peer[1..]);
        let provider = self.provider()?;
        let mut public = NCRYPT_KEY_HANDLE::default();
        // SAFETY: the peer's key is imported into the key's own (borrowed) provider and freed
        // below; the borrowed provider is never freed.
        check(
            unsafe {
                NCryptImportKey(
                    provider,
                    None,
                    BCRYPT_ECCPUBLIC_BLOB,
                    None,
                    &mut public,
                    &blob,
                    NCRYPT_SILENT_FLAG,
                )
            },
            "NCryptImportKey (the slot's ephemeral key)",
        )?;
        let public = Key {
            h: public,
            owned: true,
            _provider: None,
        };
        let mut secret = NCRYPT_SECRET_HANDLE::default();
        // SAFETY: both handles are live; `secret` is freed below.
        check(
            unsafe { NCryptSecretAgreement(self.h, public.h, &mut secret, flags(silent)) },
            "NCryptSecretAgreement",
        )?;
        let secret = Secret(secret);
        let hash = wz_bytes("SHA256");
        let params = Params::new(&[(KDF_HASH_ALGORITHM, &hash), (KDF_HMAC_KEY, context)]);
        let mut prk = Zeroizing::new([0; 32]);
        let mut n = 0u32;
        // SAFETY: the parameters outlive the call; the output is 32 bytes.
        check(
            unsafe {
                NCryptDeriveKey(
                    secret.0,
                    BCRYPT_KDF_HMAC,
                    Some(params.desc()),
                    Some(&mut prk[..]),
                    &mut n,
                    0,
                )
            },
            "NCryptDeriveKey (HMAC)",
        )?;
        if n != 32 {
            return Err(WinError {
                code: 0,
                what: format!("BCRYPT_KDF_HMAC gave {n} bytes, not 32"),
            });
        }
        Ok(prk)
    }

    /// Signs `hash` (bhive.md §13.4): RSA-PSS with a 32-byte salt or PKCS #1 v1.5, both with
    /// SHA-256; ECDSA as `r ‖ s`, which is what CNG gives.
    pub fn sign_hash(&self, algorithm: Algorithm, hash: &[u8], silent: bool) -> WinResult<Vec<u8>> {
        let pss = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            cbSalt: 32,
        };
        let pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        };
        let (pad, f) = match algorithm {
            Algorithm::RsaPss => (Some(&pss as *const _ as *const c_void), NCRYPT_PAD_PSS_FLAG),
            Algorithm::RsaPkcs1 => (
                Some(&pkcs1 as *const _ as *const c_void),
                NCRYPT_PAD_PKCS1_FLAG,
            ),
            _ => (None, NCRYPT_FLAGS(0)),
        };
        let f = f | flags(silent);
        let mut n = 0u32;
        // SAFETY: a size query, then a signature into a buffer of that size.
        unsafe {
            check(
                NCryptSignHash(self.h, pad, hash, None, &mut n, f),
                "NCryptSignHash",
            )?;
            let mut sig = vec![0; n as usize];
            check(
                NCryptSignHash(self.h, pad, hash, Some(&mut sig), &mut n, f),
                "NCryptSignHash",
            )?;
            sig.truncate(n as usize);
            Ok(sig)
        }
    }

    /// Deletes a persisted key. Not silent: the TPM's provider refuses the silent flag here.
    pub fn delete(mut self) -> WinResult<()> {
        // SAFETY: on success the call frees the handle too, so it isn't freed again.
        check(unsafe { NCryptDeleteKey(self.h, 0) }, "NCryptDeleteKey")?;
        self.owned = false;
        Ok(())
    }
}

/// An agreed secret, freed when dropped.
struct Secret(NCRYPT_SECRET_HANDLE);

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

/// The uncompressed point of a `BCRYPT_ECCPUBLIC_BLOB`: `{magic, cbKey} ‖ X ‖ Y`.
pub fn point_of_blob(blob: &[u8]) -> Option<Vec<u8>> {
    let n = u32::from_le_bytes(blob.get(4..8)?.try_into().ok()?) as usize;
    let xy = blob.get(8..8 + 2 * n)?;
    let mut p = Vec::with_capacity(1 + xy.len());
    p.push(4);
    p.extend_from_slice(xy);
    Some(p)
}

/// The modulus and exponent of a `BCRYPT_RSAPUBLIC_BLOB`.
#[cfg(test)]
pub fn rsa_of_blob(blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let u = |i: usize| -> Option<usize> {
        Some(u32::from_le_bytes(blob.get(i..i + 4)?.try_into().ok()?) as usize)
    };
    let (e, n) = (u(8)?, u(12)?);
    let exponent = blob.get(24..24 + e)?.to_vec();
    let modulus = blob.get(24 + e..24 + e + n)?.to_vec();
    Some((modulus, exponent))
}

/// A certificate store, closed when dropped.
pub struct Store(HCERTSTORE);

// SAFETY: certificate stores may be used from any thread.
unsafe impl Send for Store {}

impl Store {
    /// The current user's system store `name` (`My`, `AddressBook`), read only: BeeZip never
    /// changes the user's stores.
    pub fn user(name: &str) -> WinResult<Self> {
        let w = wz(name);
        let flags = CERT_OPEN_STORE_FLAGS(
            CERT_SYSTEM_STORE_CURRENT_USER
                | CERT_STORE_READONLY_FLAG.0
                | CERT_STORE_OPEN_EXISTING_FLAG.0,
        );
        // SAFETY: the name outlives the call; the store is closed when dropped.
        let h = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                flags,
                Some(w.as_ptr().cast()),
            )
        }
        .map_err(|e| WinError::new(&e, "CertOpenStore"))?;
        Ok(Self(h))
    }

    /// A store in memory, for certificates a signature or a file carries.
    pub fn memory() -> WinResult<Self> {
        // SAFETY: a new store, closed when dropped.
        let h = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_MEMORY,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(0),
                None,
            )
        }
        .map_err(|e| WinError::new(&e, "CertOpenStore (memory)"))?;
        Ok(Self(h))
    }

    pub fn handle(&self) -> HCERTSTORE {
        self.0
    }

    pub fn add(&self, der: &[u8]) -> WinResult<Cert> {
        let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
        // SAFETY: `der` is read only; the context returned is ours to free.
        check(
            unsafe {
                CertAddEncodedCertificateToStore(
                    Some(self.0),
                    X509_ASN_ENCODING,
                    der,
                    CERT_STORE_ADD_ALWAYS,
                    Some(&mut ctx),
                )
            },
            "CertAddEncodedCertificateToStore",
        )?;
        Ok(Cert(ctx))
    }

    pub fn certificates(&self) -> Vec<Cert> {
        let mut out = Vec::new();
        let mut prev: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // SAFETY: the enumeration frees `prev` and returns the next context, or null.
            let c = unsafe {
                CertEnumCertificatesInStore(self.0, (!prev.is_null()).then_some(prev.cast_const()))
            };
            if c.is_null() {
                break;
            }
            prev = c;
            // SAFETY: a context the enumeration returned, duplicated so it outlives it.
            out.push(Cert(unsafe { CertDuplicateCertificateContext(Some(c)) }));
        }
        out
    }

    pub fn find_sha1(&self, thumbprint: &[u8; 20]) -> Option<Cert> {
        let blob = CRYPT_INTEGER_BLOB {
            cbData: 20,
            pbData: thumbprint.as_ptr().cast_mut(),
        };
        // SAFETY: `blob` outlives the call; a found context is ours to free.
        let c = unsafe {
            CertFindCertificateInStore(
                self.0,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                Some(&blob as *const _ as *const c_void),
                None,
            )
        };
        (!c.is_null()).then(|| Cert(c))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the store is owned and closed once.
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}

/// A certificate context, freed when dropped.
pub struct Cert(*mut CERT_CONTEXT);

// SAFETY: a certificate context is reference-counted and not changed after it is made;
// CryptoAPI allows it to be used from any thread.
unsafe impl Send for Cert {}
// SAFETY: as above; nothing here changes it.
unsafe impl Sync for Cert {}

impl Clone for Cert {
    fn clone(&self) -> Self {
        // SAFETY: duplicating adds a reference, freed by the clone's drop.
        Self(unsafe { CertDuplicateCertificateContext(Some(self.0)) })
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: one reference, freed once.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
    }
}

/// Where a certificate's private key is, from its key provider information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvInfo {
    pub provider: String,
    /// 0 for a CNG provider; a legacy CryptoAPI provider's type otherwise.
    pub prov_type: u32,
}

impl Cert {
    pub fn der(&self) -> &[u8] {
        // SAFETY: the context is live and its encoded bytes are its own.
        unsafe {
            let c = &*self.0;
            std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize)
        }
    }

    fn prop(&self, id: u32) -> Option<Vec<u64>> {
        let mut n = 0u32;
        // SAFETY: a size query, then a read into an 8-byte-aligned buffer of that size.
        unsafe {
            CertGetCertificateContextProperty(self.0, id, None, &mut n).ok()?;
            let mut v = vec![0u64; (n as usize).div_ceil(8)];
            CertGetCertificateContextProperty(self.0, id, Some(v.as_mut_ptr().cast()), &mut n)
                .ok()?;
            Some(v)
        }
    }

    pub fn prov_info(&self) -> Option<ProvInfo> {
        let v = self.prop(CERT_KEY_PROV_INFO_PROP_ID)?;
        // SAFETY: the property is a CRYPT_KEY_PROV_INFO whose strings live in the same buffer.
        unsafe {
            let info = &*(v.as_ptr() as *const CRYPT_KEY_PROV_INFO);
            Some(ProvInfo {
                provider: from_pwstr(info.pwszProvName.0),
                prov_type: info.dwProvType,
            })
        }
    }

    /// The certificate has a CNG key handle attached (a key imported in memory).
    pub fn has_key_handle(&self) -> bool {
        self.prop(CERT_NCRYPT_KEY_HANDLE_PROP_ID).is_some()
    }

    /// Attaches `key` to this context, which then owns it.
    #[cfg(test)]
    pub fn attach(&self, key: Key) -> WinResult<()> {
        let h = key.release();
        // SAFETY: this property's data is the handle itself, not a pointer to it; the context
        // frees it. CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG keeps it in memory.
        check(
            unsafe {
                CertSetCertificateContextProperty(
                    self.0,
                    CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                    0x4000_0000,
                    Some(h.0 as *const c_void),
                )
            },
            "CertSetCertificateContextProperty",
        )
    }

    /// The certificate's private key, through CNG only (keys in legacy CryptoAPI providers
    /// are refused here, cleanly).
    pub fn private_key(&self, silent: bool) -> WinResult<Key> {
        self.private_key_with(silent, None)
    }

    /// [`Cert::private_key`] for a person to use: not silent, and the dialogs acquiring and
    /// using it show (a smart card's, a TPM key's PIN) belong to `window` ([`Key::parent`]).
    pub fn private_key_for(&self, window: Option<isize>) -> WinResult<Key> {
        let key = self.private_key_with(false, window)?;
        // Best effort: a dialog over the window in front is better than none.
        let _ = key.parent(window);
        Ok(key)
    }

    fn private_key_with(&self, silent: bool, window: Option<isize>) -> WinResult<Key> {
        // A key attached in memory (as a .pfx imported without persisting its keys has), which
        // CryptAcquireCertificatePrivateKey doesn't look at: the context keeps it.
        if let Some(h) = self
            .prop(CERT_NCRYPT_KEY_HANDLE_PROP_ID)
            .and_then(|v| v.first().copied())
            .and_then(|h| usize::try_from(h).ok())
        {
            return Ok(Key {
                h: NCRYPT_KEY_HANDLE(h),
                owned: false,
                _provider: None,
            });
        }
        let mut flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
        // The window a smart card's dialog belongs to while acquiring; never with the silent
        // flag, which Windows refuses beside it.
        let hwnd = window.filter(|_| !silent);
        if silent {
            flags |= CRYPT_ACQUIRE_SILENT_FLAG;
        } else if hwnd.is_some() {
            flags |= CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG;
        }
        let parameters = hwnd.as_ref().map(|h| (h as *const isize).cast::<c_void>());
        let mut h = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut spec = CERT_KEY_SPEC::default();
        let mut free = BOOL::default();
        // SAFETY: the out-pointers are ours; whether we free the key is what `free` says. With
        // CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG the parameters are the address of an HWND, which
        // `hwnd` holds for the call.
        check(
            unsafe {
                CryptAcquireCertificatePrivateKey(
                    self.0,
                    flags,
                    parameters,
                    &mut h,
                    Some(&mut spec),
                    Some(&mut free),
                )
            },
            "CryptAcquireCertificatePrivateKey",
        )?;
        Ok(Key {
            h: NCRYPT_KEY_HANDLE(h.0),
            owned: free.as_bool(),
            _provider: None,
        })
    }

    /// Checks a signature with the certificate's public key, through BCrypt.
    #[cfg(test)]
    pub fn verify(&self, algorithm: Algorithm, hash: &[u8], signature: &[u8]) -> WinResult<bool> {
        let mut key = BCRYPT_KEY_HANDLE::default();
        // SAFETY: the context and its public key info are live; the key is destroyed below.
        unsafe {
            let info = &(*(*self.0).pCertInfo).SubjectPublicKeyInfo;
            check(
                CryptImportPublicKeyInfoEx2(
                    X509_ASN_ENCODING,
                    info,
                    CRYPT_IMPORT_PUBLIC_KEY_FLAGS(0),
                    None,
                    &mut key,
                ),
                "CryptImportPublicKeyInfoEx2",
            )?;
        }
        let pss = BCRYPT_PSS_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            cbSalt: 32,
        };
        let pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        };
        let (pad, f) = match algorithm {
            Algorithm::RsaPss => (Some(&pss as *const _ as *const c_void), BCRYPT_PAD_PSS),
            Algorithm::RsaPkcs1 => (Some(&pkcs1 as *const _ as *const c_void), BCRYPT_PAD_PKCS1),
            _ => (None, BCRYPT_FLAGS(0)),
        };
        // SAFETY: the key is live until destroyed here; the inputs are read only.
        let status = unsafe { BCryptVerifySignature(key, pad, hash, signature, f) };
        // SAFETY: destroyed once.
        let _ = unsafe { BCryptDestroyKey(key) };
        Ok(status.0 >= 0)
    }

    /// Windows' chain engine on this certificate, with `extra` for the certificates a
    /// signature carries. With `revocation`, it checks revocation (which may go online to the
    /// issuer, decision 25); without, it uses only what Windows has cached.
    pub fn chain(&self, extra: Option<&Store>, revocation: bool) -> WinResult<Chain> {
        let para = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };
        let flags = if revocation {
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
        } else {
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
        };
        let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        // SAFETY: the chain context returned is freed below, after its certificates are
        // copied out.
        unsafe {
            check(
                CertGetCertificateChain(
                    None,
                    self.0,
                    None,
                    extra.map(Store::handle),
                    &para,
                    flags,
                    None,
                    &mut chain,
                ),
                "CertGetCertificateChain",
            )?;
            let c = &*chain;
            let errors = c.TrustStatus.dwErrorStatus;
            let mut certificates = Vec::new();
            if c.cChain > 0 {
                let simple = &**c.rgpChain;
                for i in 0..simple.cElement as usize {
                    let element = &**simple.rgpElement.add(i);
                    let cert = &*element.pCertContext;
                    certificates.push(
                        std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize)
                            .to_vec(),
                    );
                }
            }
            CertFreeCertificateChain(chain);
            Ok(Chain {
                errors,
                certificates,
            })
        }
    }
}

/// What Windows' chain engine made of a certificate.
#[derive(Debug, Clone)]
pub struct Chain {
    /// `CERT_TRUST_STATUS.dwErrorStatus`.
    pub errors: u32,
    /// The chain's certificates, the certificate's own first, its root last.
    pub certificates: Vec<Vec<u8>>,
}

/// A revocation server that couldn't be reached, or a certificate that names none, isn't a
/// revoked certificate.
const REVOCATION_UNKNOWN: u32 = 0x40 | 0x0100_0000;

impl Chain {
    pub fn revoked(&self) -> bool {
        self.errors & CERT_TRUST_IS_REVOKED != 0
    }

    pub fn expired(&self) -> bool {
        self.errors & (CERT_TRUST_IS_NOT_TIME_VALID | 0x2) != 0
    }

    /// Windows trusts it, leaving time and an unknown revocation status aside.
    pub fn trusted(&self) -> bool {
        self.errors & !(REVOCATION_UNKNOWN | CERT_TRUST_IS_NOT_TIME_VALID | 0x2) == 0
    }

    /// Windows would trust it but for its dates or its revocation: it leads to a root Windows
    /// trusts, with nothing else wrong. Only then do its dates and revocation mean anything.
    pub fn anchored(&self) -> bool {
        let ignored =
            REVOCATION_UNKNOWN | CERT_TRUST_IS_REVOKED | CERT_TRUST_IS_NOT_TIME_VALID | 0x2;
        self.errors & !ignored == 0
    }

    /// The chain reaches a root (trusted or not): its last certificate is a root, not an
    /// intermediate whose issuer Windows didn't find.
    pub fn complete(&self) -> bool {
        self.errors & CERT_TRUST_IS_PARTIAL_CHAIN == 0
    }
}
