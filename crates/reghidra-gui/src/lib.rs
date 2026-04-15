// Library entry point for reghidra-gui.
// The binary (main.rs) is the real entry point; this lib target exists so
// integration tests can import the crate's public types without going through
// eframe::run_native.

pub mod annotations;
pub mod app;
pub mod context_menu;
pub mod help;
pub mod palette;
pub mod syntax;
pub mod theme;
pub mod undo;
pub mod views;

pub use app::{MainView, ReghidraApp, SidePanel};
