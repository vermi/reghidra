//! Per-source-crate walkers. Each walker is responsible for turning the
//! source tree of one Rust binding crate into a [`crate::model::TypeArchive`].
//!
//! The walkers are siblings rather than a single generic implementation
//! because each source crate has its own conventions for how it
//! declares foreign functions and types:
//!
//! - `libc` uses plain `extern "C" { pub fn foo(...); }` blocks and
//!   declares types with `pub type`, `#[repr(C)] pub struct`, etc.
//!   These are straightforward for a `syn` walker to pick up via
//!   `ItemForeignMod`, `ItemType`, and `ItemStruct`.
//!
//! - `windows-sys` (PR 3b) uses a `windows_link::link!(...)` macro
//!   invocation whose internal DSL is not standard Rust syntax. The
//!   walker has to recognize the macro call and parse its token stream
//!   manually to recover function signatures.

pub mod libc;
pub mod rizin_sdb;
pub mod rust_ty;
pub mod windows;
