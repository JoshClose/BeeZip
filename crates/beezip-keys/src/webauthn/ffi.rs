//! webauthn.dll's structures and functions, as the Windows SDK's `webauthn.h` (10.0.26100,
//! `WEBAUTHN_API_VERSION_9`) declares them. `windows` 0.62.2's bindings stop at API version 7,
//! so every structure BeeZip passes or reads is declared here, at its newest version; the tests
//! check the fields the bindings share against them.
//!
//! - **Loading:** webauthn.dll is loaded at run time from System32 only, the first time it is
//!   needed, and stays loaded. A load-time import would stop BeeZip from starting on a Windows
//!   without it (before Windows 10 1903), and would be looked for in the application's folder
//!   first. Functions newer than API version 1 are looked up one by one.
//! - **Versions:** each options structure says its version in `dwVersion`. BeeZip fills the
//!   newest one the machine's API version knows ([`make_options_version`],
//!   [`get_options_version`]) and leaves the rest zero; a structure Windows returns is read only
//!   as far as its own `dwVersion` says.
#![allow(unsafe_code)]
// Declared as webauthn.h has them: not every field is read or written.
#![allow(dead_code)]

use std::{ffi::c_void, sync::OnceLock};

use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_core::{PCSTR, s, w};

pub type Bool = i32;
pub type Pcwstr = *const u16;

pub const CURRENT_API: u32 = 9;

pub const RP_ENTITY_INFORMATION_VERSION: u32 = 1;
pub const USER_ENTITY_INFORMATION_VERSION: u32 = 1;
pub const CLIENT_DATA_VERSION: u32 = 1;
pub const COSE_CREDENTIAL_PARAMETER_VERSION: u32 = 1;
pub const CREDENTIAL_VERSION: u32 = 1;
pub const GET_CREDENTIALS_OPTIONS_VERSION: u32 = 1;

pub const COSE_ALGORITHM_ECDSA_P256_WITH_SHA256: i32 = -7;
pub const COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256: i32 = -257;

pub const AUTHENTICATOR_ATTACHMENT_ANY: u32 = 0;
pub const AUTHENTICATOR_ATTACHMENT_PLATFORM: u32 = 1;
pub const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM: u32 = 2;

pub const USER_VERIFICATION_REQUIREMENT_REQUIRED: u32 = 1;
pub const USER_VERIFICATION_REQUIREMENT_DISCOURAGED: u32 = 3;

pub const ATTESTATION_CONVEYANCE_PREFERENCE_NONE: u32 = 1;

/// In `GET_ASSERTION_OPTIONS.dwFlags`: the hmac-secret salts go to the authenticator as they
/// are; without it Windows hashes them as WebAuthn's PRF does.
pub const AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG: u32 = 0x0010_0000;
pub const CTAP_ONE_HMAC_SECRET_LENGTH: u32 = 32;

pub const CREDENTIAL_TYPE_PUBLIC_KEY: Pcwstr = w!("public-key").as_ptr();
pub const HASH_ALGORITHM_SHA_256: Pcwstr = w!("SHA-256").as_ptr();
pub const EXTENSIONS_IDENTIFIER_HMAC_SECRET: Pcwstr = w!("hmac-secret").as_ptr();

/// HRESULTs webauthn.dll returns (webauthn.h, `WebAuthNGetErrorName`).
pub mod hr {
    /// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`: the person closed the dialog.
    pub const CANCELLED: u32 = 0x8007_04C7;
    pub const NTE_USER_CANCELLED: u32 = 0x8009_0036;
    /// `HRESULT_FROM_WIN32(ERROR_TIMEOUT)`.
    pub const TIMEOUT: u32 = 0x8007_05B4;
    pub const NTE_NOT_FOUND: u32 = 0x8009_0011;
    pub const NTE_DEVICE_NOT_FOUND: u32 = 0x8009_0035;
    pub const NTE_EXISTS: u32 = 0x8009_000F;
    pub const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
    pub const NTE_NOT_SUPPORTED: u32 = 0x8009_0029;
    /// `HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)`.
    pub const NOT_SUPPORTED: u32 = 0x8007_0032;
}

/// `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS`' version for an API version (webauthn.h's
/// table of versions).
pub const fn make_options_version(api: u32) -> u32 {
    match api {
        0..=2 => 3,
        3 => 4,
        4 | 5 => 5,
        6 => 6,
        7 => 7,
        8 => 8,
        _ => 9,
    }
}

/// `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS`' version for an API version.
pub const fn get_options_version(api: u32) -> u32 {
    match api {
        0..=2 => 4,
        3 => 5,
        4..=6 => 6,
        7 => 7,
        8 => 8,
        _ => 9,
    }
}

/// All-zero structures: every field is an integer or a raw pointer, for which zero is valid.
macro_rules! zeroed_default {
    ($($t:ty),* $(,)?) => {$(
        impl Default for $t {
            fn default() -> Self {
                // SAFETY: integers and raw pointers only; all zero is a valid value of each.
                unsafe { std::mem::zeroed() }
            }
        }
    )*};
}

#[repr(C)]
pub struct RpEntityInformation {
    pub dw_version: u32,
    pub pwsz_id: Pcwstr,
    pub pwsz_name: Pcwstr,
    pub pwsz_icon: Pcwstr,
}

#[repr(C)]
pub struct UserEntityInformation {
    pub dw_version: u32,
    pub cb_id: u32,
    pub pb_id: *mut u8,
    pub pwsz_name: Pcwstr,
    pub pwsz_icon: Pcwstr,
    pub pwsz_display_name: Pcwstr,
}

#[repr(C)]
pub struct ClientData {
    pub dw_version: u32,
    pub cb_client_data_json: u32,
    pub pb_client_data_json: *mut u8,
    pub pwsz_hash_alg_id: Pcwstr,
}

#[repr(C)]
pub struct CoseCredentialParameter {
    pub dw_version: u32,
    pub pwsz_credential_type: Pcwstr,
    pub l_alg: i32,
}

#[repr(C)]
pub struct CoseCredentialParameters {
    pub c_credential_parameters: u32,
    pub p_credential_parameters: *mut CoseCredentialParameter,
}

#[repr(C)]
pub struct Credential {
    pub dw_version: u32,
    pub cb_id: u32,
    pub pb_id: *mut u8,
    pub pwsz_credential_type: Pcwstr,
}

#[repr(C)]
pub struct Credentials {
    pub c_credentials: u32,
    pub p_credentials: *mut Credential,
}

#[repr(C)]
pub struct CredentialEx {
    pub dw_version: u32,
    pub cb_id: u32,
    pub pb_id: *mut u8,
    pub pwsz_credential_type: Pcwstr,
    pub dw_transports: u32,
}

#[repr(C)]
pub struct CredentialList {
    pub c_credentials: u32,
    pub pp_credentials: *mut *mut CredentialEx,
}

#[repr(C)]
pub struct Extension {
    pub pwsz_extension_identifier: Pcwstr,
    pub cb_extension: u32,
    pub pv_extension: *mut c_void,
}

#[repr(C)]
pub struct Extensions {
    pub c_extensions: u32,
    pub p_extensions: *mut Extension,
}

#[repr(C)]
pub struct HmacSecretSalt {
    pub cb_first: u32,
    pub pb_first: *mut u8,
    pub cb_second: u32,
    pub pb_second: *mut u8,
}

#[repr(C)]
pub struct CredWithHmacSecretSalt {
    pub cb_cred_id: u32,
    pub pb_cred_id: *mut u8,
    pub p_hmac_secret_salt: *mut HmacSecretSalt,
}

#[repr(C)]
pub struct HmacSecretSaltValues {
    pub p_global_hmac_salt: *mut HmacSecretSalt,
    pub c_cred_with_hmac_secret_salt_list: u32,
    pub p_cred_with_hmac_secret_salt_list: *mut CredWithHmacSecretSalt,
}

/// `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS`, version 9.
#[repr(C)]
pub struct MakeCredentialOptions {
    pub dw_version: u32,
    pub dw_timeout_milliseconds: u32,
    pub credential_list: Credentials,
    pub extensions: Extensions,
    pub dw_authenticator_attachment: u32,
    pub b_require_resident_key: Bool,
    pub dw_user_verification_requirement: u32,
    pub dw_attestation_conveyance_preference: u32,
    pub dw_flags: u32,
    // Version 2.
    pub p_cancellation_id: *mut c_void,
    // Version 3.
    pub p_exclude_credential_list: *mut CredentialList,
    // Version 4.
    pub dw_enterprise_attestation: u32,
    pub dw_large_blob_support: u32,
    pub b_prefer_resident_key: Bool,
    // Version 5.
    pub b_browser_in_private_mode: Bool,
    // Version 6.
    pub b_enable_prf: Bool,
    // Version 7.
    pub p_linked_device: *mut c_void,
    pub cb_json_ext: u32,
    pub pb_json_ext: *mut u8,
    // Version 8.
    pub p_prf_global_eval: *mut HmacSecretSalt,
    pub c_credential_hints: u32,
    pub ppwsz_credential_hints: *mut Pcwstr,
    pub b_third_party_payment: Bool,
    // Version 9.
    pub pwsz_remote_web_origin: Pcwstr,
    pub cb_public_key_credential_creation_options_json: u32,
    pub pb_public_key_credential_creation_options_json: *mut u8,
    pub cb_authenticator_id: u32,
    pub pb_authenticator_id: *mut u8,
}

/// `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS`, version 9.
#[repr(C)]
pub struct GetAssertionOptions {
    pub dw_version: u32,
    pub dw_timeout_milliseconds: u32,
    pub credential_list: Credentials,
    pub extensions: Extensions,
    pub dw_authenticator_attachment: u32,
    pub dw_user_verification_requirement: u32,
    pub dw_flags: u32,
    // Version 2.
    pub pwsz_u2f_app_id: Pcwstr,
    pub pb_u2f_app_id: *mut Bool,
    // Version 3.
    pub p_cancellation_id: *mut c_void,
    // Version 4.
    pub p_allow_credential_list: *mut CredentialList,
    // Version 5.
    pub dw_cred_large_blob_operation: u32,
    pub cb_cred_large_blob: u32,
    pub pb_cred_large_blob: *mut u8,
    // Version 6.
    pub p_hmac_secret_salt_values: *mut HmacSecretSaltValues,
    pub b_browser_in_private_mode: Bool,
    // Version 7.
    pub p_linked_device: *mut c_void,
    pub b_auto_fill: Bool,
    pub cb_json_ext: u32,
    pub pb_json_ext: *mut u8,
    // Version 8.
    pub c_credential_hints: u32,
    pub ppwsz_credential_hints: *mut Pcwstr,
    // Version 9.
    pub pwsz_remote_web_origin: Pcwstr,
    pub cb_public_key_credential_request_options_json: u32,
    pub pb_public_key_credential_request_options_json: *mut u8,
    pub cb_authenticator_id: u32,
    pub pb_authenticator_id: *mut u8,
}

/// `WEBAUTHN_CREDENTIAL_ATTESTATION`, version 8. Windows allocates it.
#[repr(C)]
pub struct CredentialAttestation {
    pub dw_version: u32,
    pub pwsz_format_type: Pcwstr,
    pub cb_authenticator_data: u32,
    pub pb_authenticator_data: *mut u8,
    pub cb_attestation: u32,
    pub pb_attestation: *mut u8,
    pub dw_attestation_decode_type: u32,
    pub pv_attestation_decode: *mut c_void,
    pub cb_attestation_object: u32,
    pub pb_attestation_object: *mut u8,
    pub cb_credential_id: u32,
    pub pb_credential_id: *mut u8,
    // Version 2.
    pub extensions: Extensions,
    // Version 3.
    pub dw_used_transport: u32,
    // Version 4.
    pub b_ep_att: Bool,
    pub b_large_blob_supported: Bool,
    pub b_resident_key: Bool,
    // Version 5.
    pub b_prf_enabled: Bool,
    // Version 6.
    pub cb_unsigned_extension_outputs: u32,
    pub pb_unsigned_extension_outputs: *mut u8,
    // Version 7.
    pub p_hmac_secret: *mut HmacSecretSalt,
    pub b_third_party_payment: Bool,
    // Version 8.
    pub dw_transports: u32,
    pub cb_client_data_json: u32,
    pub pb_client_data_json: *mut u8,
    pub cb_registration_response_json: u32,
    pub pb_registration_response_json: *mut u8,
}

/// `WEBAUTHN_ASSERTION`, version 6. Windows allocates it.
#[repr(C)]
pub struct Assertion {
    pub dw_version: u32,
    pub cb_authenticator_data: u32,
    pub pb_authenticator_data: *mut u8,
    pub cb_signature: u32,
    pub pb_signature: *mut u8,
    pub credential: Credential,
    pub cb_user_id: u32,
    pub pb_user_id: *mut u8,
    // Version 2.
    pub extensions: Extensions,
    pub cb_cred_large_blob: u32,
    pub pb_cred_large_blob: *mut u8,
    pub dw_cred_large_blob_status: u32,
    // Version 3.
    pub p_hmac_secret: *mut HmacSecretSalt,
    // Version 4.
    pub dw_used_transport: u32,
    // Version 5.
    pub cb_unsigned_extension_outputs: u32,
    pub pb_unsigned_extension_outputs: *mut u8,
    // Version 6.
    pub cb_client_data_json: u32,
    pub pb_client_data_json: *mut u8,
    pub cb_authentication_response_json: u32,
    pub pb_authentication_response_json: *mut u8,
}

#[repr(C)]
pub struct GetCredentialsOptions {
    pub dw_version: u32,
    pub pwsz_rp_id: Pcwstr,
    pub b_browser_in_private_mode: Bool,
}

/// `WEBAUTHN_CREDENTIAL_DETAILS`, version 4. Windows allocates it.
#[repr(C)]
pub struct CredentialDetails {
    pub dw_version: u32,
    pub cb_credential_id: u32,
    pub pb_credential_id: *mut u8,
    pub p_rp_information: *mut RpEntityInformation,
    pub p_user_information: *mut UserEntityInformation,
    pub b_removable: Bool,
    // Version 2.
    pub b_backed_up: Bool,
    // Version 3.
    pub pwsz_authenticator_name: Pcwstr,
    pub cb_authenticator_logo: u32,
    pub pb_authenticator_logo: *mut u8,
    pub b_third_party_payment: Bool,
    // Version 4.
    pub dw_transports: u32,
}

#[repr(C)]
pub struct CredentialDetailsList {
    pub c_credential_details: u32,
    pub pp_credential_details: *mut *mut CredentialDetails,
}

zeroed_default!(MakeCredentialOptions, GetAssertionOptions);

type Proc = unsafe extern "system" fn() -> isize;
type GetApiVersionNumber = unsafe extern "system" fn() -> u32;
type IsUserVerifyingPlatformAuthenticatorAvailable = unsafe extern "system" fn(*mut Bool) -> i32;
pub type MakeCredential = unsafe extern "system" fn(
    *mut c_void,
    *const RpEntityInformation,
    *const UserEntityInformation,
    *const CoseCredentialParameters,
    *const ClientData,
    *const MakeCredentialOptions,
    *mut *mut CredentialAttestation,
) -> i32;
pub type GetAssertion = unsafe extern "system" fn(
    *mut c_void,
    Pcwstr,
    *const ClientData,
    *const GetAssertionOptions,
    *mut *mut Assertion,
) -> i32;
pub type FreeCredentialAttestation = unsafe extern "system" fn(*mut CredentialAttestation);
pub type FreeAssertion = unsafe extern "system" fn(*mut Assertion);
pub type GetErrorName = unsafe extern "system" fn(i32) -> Pcwstr;
pub type GetPlatformCredentialList =
    unsafe extern "system" fn(*const GetCredentialsOptions, *mut *mut CredentialDetailsList) -> i32;
pub type FreePlatformCredentialList = unsafe extern "system" fn(*mut CredentialDetailsList);
pub type DeletePlatformCredential = unsafe extern "system" fn(u32, *const u8) -> i32;
type GetWindow = unsafe extern "system" fn() -> *mut c_void;
type IsWindowVisible = unsafe extern "system" fn(*mut c_void) -> Bool;
type GetAncestor = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
/// `GetAncestor`'s `GA_ROOTOWNER`: up the chain of parents and owners.
const GA_ROOTOWNER: u32 = 3;

/// webauthn.dll's functions, once loaded.
pub struct Api {
    /// `WebAuthNGetApiVersionNumber`.
    pub version: u32,
    is_uvpaa: IsUserVerifyingPlatformAuthenticatorAvailable,
    pub make_credential: MakeCredential,
    pub get_assertion: GetAssertion,
    pub free_credential_attestation: FreeCredentialAttestation,
    pub free_assertion: FreeAssertion,
    get_error_name: GetErrorName,
    /// API version 4 and later.
    pub platform_credentials: Option<(GetPlatformCredentialList, FreePlatformCredentialList)>,
    pub delete_platform_credential: Option<DeletePlatformCredential>,
}

impl Api {
    /// `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`: Windows Hello is set up. Shows
    /// nothing.
    pub fn platform_authenticator(&self) -> bool {
        let mut available: Bool = 0;
        // SAFETY: a valid out pointer to a BOOL.
        let hr = unsafe { (self.is_uvpaa)(&mut available) };
        hr >= 0 && available != 0
    }

    /// `WebAuthNGetErrorName`: `NotAllowedError` and the like.
    pub fn error_name(&self, hr: i32) -> String {
        // SAFETY: the function returns a static, NUL-terminated string, or null.
        unsafe { wide_to_string((self.get_error_name)(hr)) }
    }
}

/// webauthn.dll's functions, or `None` when this Windows has no webauthn.dll.
pub fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(load).as_ref()
}

fn load() -> Option<Api> {
    // SAFETY: a NUL-terminated name; no file handle; System32 only. The module is never freed.
    let module =
        unsafe { LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok()?;
    // SAFETY: the module is loaded and stays loaded; the names are NUL-terminated.
    let get = |name: PCSTR| -> Option<Proc> { unsafe { GetProcAddress(module, name) } };
    let version: GetApiVersionNumber =
        // SAFETY: webauthn.h's signature for the function of this name.
        unsafe { std::mem::transmute::<Proc, _>(get(s!("WebAuthNGetApiVersionNumber"))?) };
    // SAFETY: as above, for each function: webauthn.h's signature for its name.
    unsafe {
        let version = version();
        let platform_credentials = if version >= 4 {
            match (
                get(s!("WebAuthNGetPlatformCredentialList")),
                get(s!("WebAuthNFreePlatformCredentialList")),
            ) {
                (Some(list), Some(free)) => Some((
                    std::mem::transmute::<Proc, GetPlatformCredentialList>(list),
                    std::mem::transmute::<Proc, FreePlatformCredentialList>(free),
                )),
                _ => None,
            }
        } else {
            None
        };
        let delete_platform_credential = if version >= 4 {
            get(s!("WebAuthNDeletePlatformCredential"))
                .map(|f| std::mem::transmute::<Proc, DeletePlatformCredential>(f))
        } else {
            None
        };
        Some(Api {
            version,
            is_uvpaa: std::mem::transmute::<Proc, IsUserVerifyingPlatformAuthenticatorAvailable>(
                get(s!("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"))?,
            ),
            make_credential: std::mem::transmute::<Proc, MakeCredential>(get(s!(
                "WebAuthNAuthenticatorMakeCredential"
            ))?),
            get_assertion: std::mem::transmute::<Proc, GetAssertion>(get(s!(
                "WebAuthNAuthenticatorGetAssertion"
            ))?),
            free_credential_attestation: std::mem::transmute::<Proc, FreeCredentialAttestation>(
                get(s!("WebAuthNFreeCredentialAttestation"))?,
            ),
            free_assertion: std::mem::transmute::<Proc, FreeAssertion>(get(s!(
                "WebAuthNFreeAssertion"
            ))?),
            get_error_name: std::mem::transmute::<Proc, GetErrorName>(get(s!(
                "WebAuthNGetErrorName"
            ))?),
            platform_credentials,
            delete_platform_credential,
        })
    }
}

/// The user32.dll functions that find a dialog's window. user32.dll is loaded the first time
/// one is looked for: when a dialog is about to show, or when the CLI picks its terminal's
/// window.
struct User32 {
    foreground: GetWindow,
    desktop: GetWindow,
    visible: IsWindowVisible,
    ancestor: GetAncestor,
}

fn user32() -> Option<&'static User32> {
    static USER32: OnceLock<Option<User32>> = OnceLock::new();
    USER32
        .get_or_init(|| {
            // SAFETY: as in `load`, for user32.dll, which stays loaded.
            let module =
                unsafe { LoadLibraryExW(w!("user32.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
                    .ok()?;
            // SAFETY: the module is loaded; the names are NUL-terminated.
            let get = |name: PCSTR| -> Option<Proc> { unsafe { GetProcAddress(module, name) } };
            // SAFETY: each function as winuser.h declares it.
            unsafe {
                Some(User32 {
                    foreground: std::mem::transmute::<Proc, GetWindow>(get(s!(
                        "GetForegroundWindow"
                    ))?),
                    desktop: std::mem::transmute::<Proc, GetWindow>(get(s!("GetDesktopWindow"))?),
                    visible: std::mem::transmute::<Proc, IsWindowVisible>(get(s!(
                        "IsWindowVisible"
                    ))?),
                    ancestor: std::mem::transmute::<Proc, GetAncestor>(get(s!("GetAncestor"))?),
                })
            }
        })
        .as_ref()
}

/// The window Windows' dialog belongs to when the caller has none: the one in front (the
/// terminal a command runs in), else the desktop, as libfido2 does.
pub fn foreground_window() -> *mut c_void {
    let Some(user32) = user32() else {
        return std::ptr::null_mut();
    };
    // SAFETY: both take nothing and return a window handle, or null.
    let window = unsafe { (user32.foreground)() };
    if window.is_null() {
        // SAFETY: as above.
        unsafe { (user32.desktop)() }
    } else {
        window
    }
}

/// Windows' answers about its windows, for [`crate::window::dialog_window`].
pub struct Desktop;

impl crate::window::Desktop for Desktop {
    fn console(&self) -> Option<isize> {
        // SAFETY: takes nothing and returns a window handle, or null.
        let window = unsafe { windows::Win32::System::Console::GetConsoleWindow() };
        (!window.0.is_null()).then_some(window.0 as isize)
    }

    fn visible(&self, window: isize) -> bool {
        // SAFETY: any handle may be asked about; one that isn't a window is not visible.
        user32().is_some_and(|u| unsafe { (u.visible)(window as *mut c_void) } != 0)
    }

    fn root_owner(&self, window: isize) -> Option<isize> {
        let user32 = user32()?;
        // SAFETY: as above; null for a handle that isn't a window.
        let top = unsafe { (user32.ancestor)(window as *mut c_void, GA_ROOTOWNER) };
        (!top.is_null()).then_some(top as isize)
    }

    fn foreground(&self) -> Option<isize> {
        let user32 = user32()?;
        // SAFETY: takes nothing and returns a window handle, or null.
        let window = unsafe { (user32.foreground)() };
        (!window.is_null()).then_some(window as isize)
    }
}

/// A NUL-terminated UTF-16 copy of `s`.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A Rust string from a NUL-terminated UTF-16 one.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
pub unsafe fn wide_to_string(p: Pcwstr) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so every unit read up to the NUL is in it.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// The `len` bytes at `p`, or none when `p` is null.
///
/// # Safety
/// `p` is null or points to `len` readable bytes.
pub unsafe fn bytes<'a>(p: *const u8, len: u32) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's promise.
    unsafe { std::slice::from_raw_parts(p, len as usize) }
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use windows::Win32::Networking::WindowsWebServices as w;

    use super::*;

    /// The fields `windows` 0.62.2's bindings (API version 7, from Microsoft's metadata) share
    /// with the structures declared here sit at the same offsets, and each binding ends where
    /// the next version's fields begin.
    #[test]
    fn layouts_match_the_bindings() {
        macro_rules! same {
            ($ours:ty, $theirs:ty, $($a:ident = $b:ident),* $(,)?) => {$(
                assert_eq!(
                    offset_of!($ours, $a),
                    offset_of!($theirs, $b),
                    concat!(stringify!($ours), ".", stringify!($a)),
                );
            )*};
        }
        same!(
            MakeCredentialOptions,
            w::WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
            dw_version = dwVersion,
            dw_timeout_milliseconds = dwTimeoutMilliseconds,
            credential_list = CredentialList,
            extensions = Extensions,
            dw_authenticator_attachment = dwAuthenticatorAttachment,
            b_require_resident_key = bRequireResidentKey,
            dw_user_verification_requirement = dwUserVerificationRequirement,
            dw_attestation_conveyance_preference = dwAttestationConveyancePreference,
            dw_flags = dwFlags,
            p_cancellation_id = pCancellationId,
            p_exclude_credential_list = pExcludeCredentialList,
            dw_enterprise_attestation = dwEnterpriseAttestation,
            dw_large_blob_support = dwLargeBlobSupport,
            b_prefer_resident_key = bPreferResidentKey,
            b_browser_in_private_mode = bBrowserInPrivateMode,
            b_enable_prf = bEnablePrf,
            p_linked_device = pLinkedDevice,
            cb_json_ext = cbJsonExt,
            pb_json_ext = pbJsonExt
        );
        assert_eq!(
            size_of::<w::WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS>(),
            offset_of!(MakeCredentialOptions, p_prf_global_eval)
        );
        same!(
            GetAssertionOptions,
            w::WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
            dw_version = dwVersion,
            dw_timeout_milliseconds = dwTimeoutMilliseconds,
            credential_list = CredentialList,
            extensions = Extensions,
            dw_authenticator_attachment = dwAuthenticatorAttachment,
            dw_user_verification_requirement = dwUserVerificationRequirement,
            dw_flags = dwFlags,
            pwsz_u2f_app_id = pwszU2fAppId,
            pb_u2f_app_id = pbU2fAppId,
            p_cancellation_id = pCancellationId,
            p_allow_credential_list = pAllowCredentialList,
            dw_cred_large_blob_operation = dwCredLargeBlobOperation,
            cb_cred_large_blob = cbCredLargeBlob,
            pb_cred_large_blob = pbCredLargeBlob,
            p_hmac_secret_salt_values = pHmacSecretSaltValues,
            b_browser_in_private_mode = bBrowserInPrivateMode,
            p_linked_device = pLinkedDevice,
            b_auto_fill = bAutoFill,
            cb_json_ext = cbJsonExt,
            pb_json_ext = pbJsonExt
        );
        assert_eq!(
            size_of::<w::WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS>(),
            offset_of!(GetAssertionOptions, c_credential_hints)
        );
        same!(
            CredentialAttestation,
            w::WEBAUTHN_CREDENTIAL_ATTESTATION,
            dw_version = dwVersion,
            pwsz_format_type = pwszFormatType,
            cb_authenticator_data = cbAuthenticatorData,
            pb_authenticator_data = pbAuthenticatorData,
            cb_attestation = cbAttestation,
            pb_attestation = pbAttestation,
            dw_attestation_decode_type = dwAttestationDecodeType,
            pv_attestation_decode = pvAttestationDecode,
            cb_attestation_object = cbAttestationObject,
            pb_attestation_object = pbAttestationObject,
            cb_credential_id = cbCredentialId,
            pb_credential_id = pbCredentialId,
            extensions = Extensions,
            dw_used_transport = dwUsedTransport,
            b_ep_att = bEpAtt,
            b_large_blob_supported = bLargeBlobSupported,
            b_resident_key = bResidentKey,
            b_prf_enabled = bPrfEnabled,
            cb_unsigned_extension_outputs = cbUnsignedExtensionOutputs,
            pb_unsigned_extension_outputs = pbUnsignedExtensionOutputs
        );
        assert_eq!(
            size_of::<w::WEBAUTHN_CREDENTIAL_ATTESTATION>(),
            offset_of!(CredentialAttestation, p_hmac_secret)
        );
        same!(
            Assertion,
            w::WEBAUTHN_ASSERTION,
            dw_version = dwVersion,
            cb_authenticator_data = cbAuthenticatorData,
            pb_authenticator_data = pbAuthenticatorData,
            cb_signature = cbSignature,
            pb_signature = pbSignature,
            credential = Credential,
            cb_user_id = cbUserId,
            pb_user_id = pbUserId,
            extensions = Extensions,
            cb_cred_large_blob = cbCredLargeBlob,
            pb_cred_large_blob = pbCredLargeBlob,
            dw_cred_large_blob_status = dwCredLargeBlobStatus,
            p_hmac_secret = pHmacSecret,
            dw_used_transport = dwUsedTransport,
            cb_unsigned_extension_outputs = cbUnsignedExtensionOutputs,
            pb_unsigned_extension_outputs = pbUnsignedExtensionOutputs
        );
        assert_eq!(
            size_of::<w::WEBAUTHN_ASSERTION>(),
            offset_of!(Assertion, cb_client_data_json)
        );
        same!(
            CredentialDetails,
            w::WEBAUTHN_CREDENTIAL_DETAILS,
            dw_version = dwVersion,
            cb_credential_id = cbCredentialID,
            pb_credential_id = pbCredentialID,
            p_rp_information = pRpInformation,
            p_user_information = pUserInformation,
            b_removable = bRemovable
        );
        same!(
            HmacSecretSaltValues,
            w::WEBAUTHN_HMAC_SECRET_SALT_VALUES,
            p_global_hmac_salt = pGlobalHmacSalt,
            c_cred_with_hmac_secret_salt_list = cCredWithHmacSecretSaltList,
            p_cred_with_hmac_secret_salt_list = pCredWithHmacSecretSaltList
        );
        macro_rules! same_size {
            ($($ours:ty = $theirs:ty),* $(,)?) => {$(
                assert_eq!(size_of::<$ours>(), size_of::<$theirs>(), stringify!($ours));
            )*};
        }
        same_size!(
            RpEntityInformation = w::WEBAUTHN_RP_ENTITY_INFORMATION,
            UserEntityInformation = w::WEBAUTHN_USER_ENTITY_INFORMATION,
            ClientData = w::WEBAUTHN_CLIENT_DATA,
            CoseCredentialParameter = w::WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
            CoseCredentialParameters = w::WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
            Credential = w::WEBAUTHN_CREDENTIAL,
            Credentials = w::WEBAUTHN_CREDENTIALS,
            CredentialEx = w::WEBAUTHN_CREDENTIAL_EX,
            CredentialList = w::WEBAUTHN_CREDENTIAL_LIST,
            Extension = w::WEBAUTHN_EXTENSION,
            Extensions = w::WEBAUTHN_EXTENSIONS,
            HmacSecretSalt = w::WEBAUTHN_HMAC_SECRET_SALT,
            CredWithHmacSecretSalt = w::WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT,
            GetCredentialsOptions = w::WEBAUTHN_GET_CREDENTIALS_OPTIONS,
            CredentialDetailsList = w::WEBAUTHN_CREDENTIAL_DETAILS_LIST,
        );
        assert_eq!(
            AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG,
            w::WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG
        );
    }

    /// The newest fields, which the bindings lack, where the SDK's webauthn.h puts them on
    /// 64-bit Windows (measured with `offsetof` and MSVC against the 10.0.26100 header).
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn newest_fields_are_where_the_header_puts_them() {
        assert_eq!(offset_of!(MakeCredentialOptions, p_prf_global_eval), 128);
        assert_eq!(offset_of!(MakeCredentialOptions, c_credential_hints), 136);
        assert_eq!(
            offset_of!(MakeCredentialOptions, b_third_party_payment),
            152
        );
        assert_eq!(
            offset_of!(MakeCredentialOptions, pwsz_remote_web_origin),
            160
        );
        assert_eq!(offset_of!(MakeCredentialOptions, cb_authenticator_id), 184);
        assert_eq!(offset_of!(MakeCredentialOptions, pb_authenticator_id), 192);
        assert_eq!(size_of::<MakeCredentialOptions>(), 200);
        assert_eq!(offset_of!(GetAssertionOptions, c_credential_hints), 144);
        assert_eq!(offset_of!(GetAssertionOptions, pwsz_remote_web_origin), 160);
        assert_eq!(offset_of!(GetAssertionOptions, pb_authenticator_id), 192);
        assert_eq!(size_of::<GetAssertionOptions>(), 200);
        assert_eq!(offset_of!(CredentialAttestation, p_hmac_secret), 144);
        assert_eq!(offset_of!(CredentialAttestation, dw_transports), 156);
        assert_eq!(
            offset_of!(CredentialAttestation, pb_registration_response_json),
            184
        );
        assert_eq!(size_of::<CredentialAttestation>(), 192);
        assert_eq!(offset_of!(Assertion, cb_client_data_json), 136);
        assert_eq!(offset_of!(Assertion, pb_authentication_response_json), 160);
        assert_eq!(size_of::<Assertion>(), 168);
        assert_eq!(offset_of!(CredentialDetails, dw_transports), 68);
        assert_eq!(size_of::<CredentialDetails>(), 72);
    }

    #[test]
    fn options_versions_follow_the_api_version() {
        assert_eq!(make_options_version(1), 3);
        assert_eq!(make_options_version(4), 5);
        assert_eq!(make_options_version(6), 6);
        assert_eq!(make_options_version(9), 9);
        assert_eq!(make_options_version(12), 9);
        assert_eq!(get_options_version(1), 4);
        assert_eq!(get_options_version(3), 5);
        assert_eq!(get_options_version(4), 6);
        assert_eq!(get_options_version(6), 6);
        assert_eq!(get_options_version(9), 9);
        assert_eq!(get_options_version(12), 9);
        // The structures declared here are those of the newest API version BeeZip knows.
        assert_eq!(make_options_version(CURRENT_API), 9);
        assert_eq!(get_options_version(CURRENT_API), 9);
    }

    #[test]
    fn wide_strings_round_trip() {
        let w = wide("bée");
        assert_eq!(w.last(), Some(&0));
        // SAFETY: NUL-terminated.
        assert_eq!(unsafe { wide_to_string(w.as_ptr()) }, "bée");
        // SAFETY: null is allowed.
        assert_eq!(unsafe { wide_to_string(std::ptr::null()) }, "");
    }
}
