use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use beezip_core::format::bhive::crypt::{
    Curve,
    cert::{Certificate, KeyAlgorithm},
};

use crate::{
    CliSpec, CmdError, Command, Effect, JobCtx, Surfaces,
    crypt::{CertificateInfo, KeyHomeName},
};

/// What a listed certificate is wanted for.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum CertPurposeName {
    /// Every certificate in your stores.
    #[default]
    All,
    /// Those an archive can be encrypted to.
    Encrypt,
    /// Those whose private key is here and can sign.
    Sign,
}

/// List the certificates in your stores (Personal and Other People on Windows, the Keychain on
/// macOS) that can encrypt archives or sign them, with why the others can't.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct CertificatesListInput {
    /// Which to list [default: all].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<CertPurposeName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CertificatesListOutput {
    pub certificates: Vec<CertificateInfo>,
}

pub struct CertificatesList;

impl Command for CertificatesList {
    const NAME: &'static str = "certificates.list";
    const EFFECT: Effect = Effect::ReadOnly;
    const SURFACES: Surfaces = Surfaces::ALL;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "list",
        aliases: &["ls"],
        group: Some("certificates"),
    });

    type Input = CertificatesListInput;
    type Output = CertificatesListOutput;

    fn run(
        input: CertificatesListInput,
        _: &mut JobCtx,
    ) -> Result<CertificatesListOutput, CmdError> {
        let purpose = input.purpose.unwrap_or_default();
        let certificates = store_certificates()?
            .into_iter()
            .filter(|c| match purpose {
                CertPurposeName::All => true,
                CertPurposeName::Encrypt => c.can_encrypt,
                CertPurposeName::Sign => c.can_sign,
            })
            .collect();
        Ok(CertificatesListOutput { certificates })
    }

    fn human(out: &CertificatesListOutput) -> Option<String> {
        if out.certificates.is_empty() {
            return Some("no certificates".into());
        }
        let lines: Vec<String> = out
            .certificates
            .iter()
            .map(|c| {
                let can = match (c.can_encrypt, c.can_sign) {
                    (true, true) => "encrypts, signs",
                    (true, false) => "encrypts",
                    (false, true) => "signs",
                    (false, false) => "neither",
                };
                format!(
                    "{}  {} ({}; {can}{})\n    issued by {}",
                    c.thumbprint,
                    c.subject,
                    c.algorithm,
                    if c.trusted { "" } else { "; not trusted" },
                    c.issuer
                )
            })
            .collect();
        Some(lines.join("\n"))
    }
}

/// A certificate as `certificates.list` shows it.
#[cfg_attr(
    not(any(windows, target_os = "macos")),
    allow(dead_code, reason = "Linux has no certificate store BeeZip lists")
)]
pub fn info(
    c: &Certificate,
    store: Option<String>,
    key: Option<KeyHomeName>,
    trusted: bool,
) -> CertificateInfo {
    let refused = c.slot_kind().err();
    // Its key is here, it may sign with an algorithm readers check (docs/bhive.md §13.4: an RSA
    // key of 2,048 to 8,192 bits, P-256 or P-384), and it hasn't expired.
    let can_sign = key.is_some() && c.sign_algorithm().is_ok() && !c.expired(crate::protect::now());
    CertificateInfo {
        thumbprint: c.thumbprint.iter().map(|b| format!("{b:02X}")).collect(),
        subject: c.subject.clone(),
        issuer: c.issuer.clone(),
        not_after: c.not_after,
        algorithm: match c.algorithm {
            KeyAlgorithm::Rsa { bits } => format!("rsa-{bits}"),
            KeyAlgorithm::Ec(Curve::P256) => "ec-p256".into(),
            KeyAlgorithm::Ec(Curve::P384) => "ec-p384".into(),
            KeyAlgorithm::Other => "other".into(),
        },
        store,
        key,
        can_encrypt: refused.is_none(),
        can_sign,
        refused,
        trusted,
    }
}

/// Personal and Other People, on Windows.
#[cfg(windows)]
fn store_certificates() -> Result<Vec<CertificateInfo>, CmdError> {
    use beezip_keys::cng::KeyHome;
    Ok(beezip_keys::cng::certificates()?
        .iter()
        .map(|c| {
            let store = match c.store.as_str() {
                "My" => "personal".to_owned(),
                "AddressBook" => "other-people".to_owned(),
                other => other.to_lowercase(),
            };
            let key = c.key.map(|k| match k {
                KeyHome::Software => KeyHomeName::Software,
                KeyHome::SmartCard => KeyHomeName::SmartCard,
                KeyHome::Tpm => KeyHomeName::Tpm,
            });
            info(&c.certificate, Some(store), key, c.trusted)
        })
        .collect())
}

/// The Keychain's identities (personal) and certificates without a key (other people), on
/// macOS. A key in the Keychain is in software, as far as BeeZip can tell.
#[cfg(target_os = "macos")]
fn store_certificates() -> Result<Vec<CertificateInfo>, CmdError> {
    Ok(beezip_keys::mac::certificates()?
        .iter()
        .map(|c| {
            let key = c.key.then_some(KeyHomeName::Software);
            info(&c.certificate, Some(c.store.clone()), key, c.trusted)
        })
        .collect())
}

/// No certificate store is read on Linux: certificate files work everywhere.
#[cfg(not(any(windows, target_os = "macos")))]
fn store_certificates() -> Result<Vec<CertificateInfo>, CmdError> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_certificate_can_do() {
        let c = Certificate {
            der: vec![1],
            spki: vec![2],
            algorithm: KeyAlgorithm::Ec(Curve::P256),
            subject: "CN=Alice".into(),
            issuer: "CN=CA".into(),
            not_before: 0,
            not_after: 2_000_000_000,
            key_encipherment: None,
            key_agreement: Some(false),
            digital_signature: Some(true),
            thumbprint: [0xAB; 20],
        };
        let i = info(&c, None, Some(KeyHomeName::Software), true);
        assert_eq!(i.thumbprint, "AB".repeat(20));
        assert_eq!(i.algorithm, "ec-p256");
        assert!(i.can_sign);
        // Whether it can encrypt is the certificate's to say; it says why when it can't.
        assert_eq!(i.can_encrypt, i.refused.is_none());
        let i = info(&c, None, None, true);
        assert!(!i.can_sign, "no private key here");
    }

    /// This system's stores, whatever they hold: listing never fails, and every certificate is
    /// in one of the two stores BeeZip names (none on Linux).
    #[test]
    fn this_systems_stores_list() {
        let listed = store_certificates().unwrap();
        for c in &listed {
            assert_eq!(c.thumbprint.len(), 40);
            assert!(
                matches!(c.store.as_deref(), Some("personal" | "other-people")),
                "{:?}",
                c.store
            );
            assert_eq!(c.can_encrypt, c.refused.is_none());
            assert!(!c.can_sign || c.key.is_some());
        }
        if cfg!(not(any(windows, target_os = "macos"))) {
            assert!(listed.is_empty());
        }
    }
}
