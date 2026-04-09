//! Loaded Data Sources panel.
//!
//! Modal `egui::Window` that lists every FLIRT signature database and
//! type archive currently affecting the open binary, with per-source
//! enable/disable checkboxes and live hit counts. The panel exists
//! because silent auto-application of analysis data sources is
//! indistinguishable from a wiring bug to the user — when an MSVC CRT
//! internal renders with no prototype, "no archive carries it" and
//! "the archive load is broken" look identical until you instrument
//! the chain. This window IS the instrumentation.
//!
//! State:
//!   * Open/closed flag lives on `ReghidraApp::data_sources_open`.
//!   * Enable flags / hit counts live on `Project` so toggles persist
//!     across re-renders within a session. Not session-persisted in v1.
//!
//! Toggling a FLIRT db forces a full re-analysis (renames are baked
//! in at analysis time); toggling a type archive only invalidates the
//! decompile cache.

use crate::app::ReghidraApp;

/// Render the Loaded Data Sources window. Caller is `ReghidraApp::ui`
/// which calls this once per frame after the central panel; the
/// window only paints when `app.data_sources_open` is true.
pub fn render_window(app: &mut ReghidraApp, ctx: &egui::Context) {
    if !app.data_sources_open {
        return;
    }

    // Local copy of the open flag so the close button doesn't fight
    // egui's `open` arg over &mut self borrows.
    let mut open = true;
    let mut force_decompile_invalidate = false;

    egui::Window::new("Loaded Data Sources")
        .open(&mut open)
        .resizable(true)
        .default_width(560.0)
        .default_height(420.0)
        .show(ctx, |ui| {
            let Some(project) = app.project.as_mut() else {
                ui.label("No binary loaded.");
                return;
            };

            ui.label(
                "Sources auto-applied to the current binary. Toggle a row to \
                 disable it; FLIRT toggles re-run analysis, type-archive \
                 toggles only re-render the decompile.",
            );
            ui.add_space(6.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                render_flirt_section(ui, project);
                ui.add_space(12.0);
                if render_type_archive_section(ui, project) {
                    force_decompile_invalidate = true;
                }
            });
        });

    if !open {
        app.data_sources_open = false;
    }
    if force_decompile_invalidate {
        // Type-archive toggles don't re-run analysis, but they do
        // change what `decompile_annotated` returns. Invalidating the
        // cache forces the next decompile-view paint to call back into
        // the project with the new effective archive set.
        app.decompile_cache = None;
    }
}

fn render_flirt_section(ui: &mut egui::Ui, project: &mut reghidra_core::Project) {
    ui.heading("FLIRT signature databases");

    if project.bundled_dbs.is_empty() && project.user_dbs.is_empty() {
        ui.label("(no signature databases loaded)");
        return;
    }

    // Snapshot the names/counts/hits up front so we don't fight the
    // borrow checker on `&mut project` while iterating.
    let bundled: Vec<(String, usize, usize, bool)> = project
        .bundled_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| {
            (
                db.header.name.clone(),
                db.signature_count,
                project.bundled_db_hits.get(i).copied().unwrap_or(0),
                project.bundled_db_enabled.get(i).copied().unwrap_or(true),
            )
        })
        .collect();
    let user: Vec<(String, usize, usize, bool)> = project
        .user_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| {
            (
                db.header.name.clone(),
                db.signature_count,
                project.user_db_hits.get(i).copied().unwrap_or(0),
                project.user_db_enabled.get(i).copied().unwrap_or(true),
            )
        })
        .collect();

    let mut bundled_toggle: Option<(usize, bool)> = None;
    let mut user_toggle: Option<(usize, bool)> = None;

    egui::Grid::new("flirt_table")
        .num_columns(5)
        .striped(true)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label("");
            ui.label(egui::RichText::new("Name").strong());
            ui.label(egui::RichText::new("Kind").strong());
            ui.label(egui::RichText::new("Sigs").strong());
            ui.label(egui::RichText::new("Hits").strong());
            ui.end_row();

            for (i, (name, sig_count, hits, enabled)) in bundled.into_iter().enumerate() {
                let mut on = enabled;
                ui.checkbox(&mut on, "");
                ui.label(name);
                ui.label("Bundled");
                ui.label(format!("{sig_count}"));
                ui.label(format!("{hits}"));
                ui.end_row();
                if on != enabled {
                    bundled_toggle = Some((i, on));
                }
            }
            for (i, (name, sig_count, hits, enabled)) in user.into_iter().enumerate() {
                let mut on = enabled;
                ui.checkbox(&mut on, "");
                ui.label(name);
                ui.label("User");
                ui.label(format!("{sig_count}"));
                ui.label(format!("{hits}"));
                ui.end_row();
                if on != enabled {
                    user_toggle = Some((i, on));
                }
            }
        });

    if let Some((i, on)) = bundled_toggle {
        project.set_bundled_db_enabled(i, on);
    }
    if let Some((i, on)) = user_toggle {
        project.set_user_db_enabled(i, on);
    }
}

/// Render the type archive section. Returns `true` if any toggle was
/// applied so the caller knows to invalidate the decompile cache.
fn render_type_archive_section(ui: &mut egui::Ui, project: &mut reghidra_core::Project) -> bool {
    ui.heading("Type archives");

    if project.type_archives.is_empty() {
        ui.label("(no type archives loaded for this format/architecture)");
        return false;
    }

    let archives: Vec<(String, usize, usize, bool)> = project
        .type_archives
        .iter()
        .enumerate()
        .map(|(i, a)| {
            (
                a.name.clone(),
                a.functions.len(),
                project.type_archive_hits.get(i).copied().unwrap_or(0),
                project.type_archive_enabled.get(i).copied().unwrap_or(true),
            )
        })
        .collect();

    let mut toggle: Option<(usize, bool)> = None;

    egui::Grid::new("type_archive_table")
        .num_columns(4)
        .striped(true)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label("");
            ui.label(egui::RichText::new("Name").strong());
            ui.label(egui::RichText::new("Functions").strong());
            ui.label(egui::RichText::new("Hits").strong());
            ui.end_row();

            for (i, (name, fn_count, hits, enabled)) in archives.into_iter().enumerate() {
                let mut on = enabled;
                ui.checkbox(&mut on, "");
                ui.label(name);
                ui.label(format!("{fn_count}"));
                ui.label(format!("{hits}"));
                ui.end_row();
                if on != enabled {
                    toggle = Some((i, on));
                }
            }
        });

    if let Some((i, on)) = toggle {
        project.set_type_archive_enabled(i, on);
        return true;
    }
    false
}
