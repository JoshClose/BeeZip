//! The Microsoft Store package (docs/M12.md): its identity, which Partner Center assigned to the
//! product and which never changes. `xtask dist` writes it into the package's manifest; the menu
//! DLL knows the package by its own class, the Store root.

/// `Package/Identity/Name`.
pub const NAME: &str = "CloseConsultingInc.BeeZip";
/// `Package/Identity/Publisher`: Partner Center's, not a certificate's. Microsoft signs the
/// package with it after certification.
pub const PUBLISHER: &str = "CN=B81ECA8F-95E1-4C2B-B747-FE4DA97C8BFC";
/// `Package/Properties/PublisherDisplayName`: the developer account's publisher name.
pub const PUBLISHER_DISPLAY_NAME: &str = "Close Consulting, Inc";
/// The package family name: the name and a hash of the publisher.
pub const FAMILY: &str = "CloseConsultingInc.BeeZip_x5m1y1n6e4ce4";
/// The product's Store ID, for links to its page.
pub const STORE_ID: &str = "9P9HHSVMM3M3";
/// The app's ID in the manifest; with [`FAMILY`], its AUMID (`<family>!BeeZip`).
pub const APP_ID: &str = "BeeZip";
