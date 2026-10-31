//! In-process schemas and privileged builder administration boundary.
// The admin library reuses the bounded JSON parser and provider types; the
// executable also compiles this module for full DSSE verification.
#[allow(dead_code)]
pub mod build_attestation;
mod builder_admin;
pub mod builder_mutation;
pub mod builder_transaction;
pub mod builder_trust;
mod directory_scan;
