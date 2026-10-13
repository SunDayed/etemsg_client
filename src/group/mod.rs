//! Group (MLS / RFC 9420) module.
//!
//! Strictly one-way layering: `adapter` is the only layer touching openmls, `state`/`errors` are plain data, `service`/`storage` depend on them.

pub mod adapter;
pub mod errors;
pub mod state;
pub mod net_transport;
pub mod runtime;
pub mod service;
pub mod storage;
pub mod transport;

#[cfg(test)]
mod service_tests;

pub use errors::{MlsError, MlsResult};
pub use state::{GroupRole, GroupState};

