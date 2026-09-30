//! LNURLwallet, native: a desktop wallet for LNURLcash (LUD-25) bearer notes.
//!
//! The protocol - request building, response parsing, error taxonomy,
//! signatures - is lnurlcash-core. This crate adds the parts that are a
//! wallet's own: an encrypted store, the persist-before-disclose ordering
//! around each mutation, mint key pinning, and the UI.

#![forbid(unsafe_code)]
// a GUI app: no console window next to it on Windows (release builds only,
// so `cargo run` still shows logs and panics)
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod http;
mod keys;
mod lud25;
#[cfg(test)]
mod mock_mint;
#[cfg(test)]
mod reference_mint;
mod store;
mod wallet;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("LNURLwallet")
            .with_inner_size([560.0, 720.0])
            .with_min_inner_size([420.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "LNURLwallet",
        options,
        Box::new(|_cc| Ok(Box::new(app::App::new(store::default_path())))),
    )
}
