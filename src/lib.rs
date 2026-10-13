//! msg-client-rust library crate used by the client binary.
//! Holds no initialization logic: the runtime database and identity files are copied into `dist/` by `build.sh` when packaging.

pub mod core;
pub mod crypto;
pub mod group;
pub mod log;
pub mod net;
pub mod store;
pub mod ui;
