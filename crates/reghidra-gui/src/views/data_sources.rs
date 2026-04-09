//! Loaded Data Sources panel.
//!
//! Modal `egui::Window` that lists every FLIRT signature database and
//! type archive shipped with the binary, with per-source enable/disable
//! checkboxes and live hit counts. The panel exists because silent
//! auto-application of analysis data sources is indistinguishable from
//! a wiring bug to the user — when an MSVC CRT internal renders with
//! no prototype, "no archive carries it" and "the archive load is
//! broken" look identical until you instrument the chain. This window
//! IS the instrumentation.
//!
//! State:
//!   * Open/closed flag lives on `ReghidraApp::data_sources_open`.
//!   * Enable flags / hit counts live on `Project` so toggles persist
//!     across re-renders within a session. Not session-persisted in v1.
//!
//! "Loaded vs available" model: the panel enumerates every embedded
//! archive/sig file regardless of whether the format/arch heuristic
//! auto-loaded it. Auto-loaded entries start checked; the rest start
//! unchecked. Checking an unchecked entry triggers a lazy parse via
//! `Project::load_type_archive_by_stem` / `Project::load_bundled_sig`
//! and then enables it like any other source. Unchecking keeps the
//! parsed data in memory (cheap) so re-checking is instant.
//!
//! Toggling a FLIRT db forces a full re-analysis (renames are baked
//! in at analysis time); toggling a type archive only invalidates the
//! decompile cache.

use crate::app::ReghidraApp;
use std::collections::BTreeMap;

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
        .default_width(620.0)
        .default_height(480.0)
        .show(ctx, |ui| {
            let Some(project) = app.project.as_mut() else {
                ui.label("No binary loaded.");
                return;
            };

            ui.label(
                "Every signature db and type archive shipped with reghidra. \
                 Entries auto-loaded for this binary's format/arch start \
                 checked; the rest are listed but unchecked — toggling one \
                 lazy-loads it. FLIRT toggles re-run analysis; type-archive \
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

// ---------------------------------------------------------------------------
// FLIRT section — tree grouped by `signatures/<format>/<arch>/<bits>` subdir
// ---------------------------------------------------------------------------

/// Snapshot of one row in the FLIRT tree. Built up front so we can
/// mutate `project` for toggle actions without fighting the borrow
/// checker on the iterator state.
struct FlirtRowSnapshot {
    subdir: String,
    stem: String,
    /// `Some(idx)` when this sig is currently parsed and lives at
    /// `project.bundled_dbs[idx]`. `None` when only the embedded `.sig`
    /// file is known and clicking the row will lazy-load it.
    loaded_idx: Option<usize>,
    enabled: bool,
    sig_count: Option<usize>,
    hits: Option<usize>,
}

/// Action requested by a single click in the FLIRT tree. Drained after
/// the immutable iteration finishes.
enum FlirtAction {
    LoadAndEnable { subdir: String, stem: String },
    SetBundledEnabled { idx: usize, enabled: bool },
    SetUserEnabled { idx: usize, enabled: bool },
}

fn render_flirt_section(ui: &mut egui::Ui, project: &mut reghidra_core::Project) {
    ui.heading("FLIRT signature databases");

    // Build the bundled tree: every embedded sig grouped by subdir,
    // joined with the parsed-db state by stem. The two sources almost
    // always agree (every parsed bundled db originated from the
    // embedded tree), but the join is by stem so a future refactor
    // that loads sigs from a non-embedded source still survives.
    let loaded_by_stem: std::collections::HashMap<&str, usize> = project
        .bundled_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| (db.header.name.as_str(), i))
        .collect();

    let mut tree: BTreeMap<String, Vec<FlirtRowSnapshot>> = BTreeMap::new();
    for sig in &project.available_bundled_sigs {
        let loaded_idx = loaded_by_stem.get(sig.stem.as_str()).copied();
        let (enabled, sig_count, hits) = match loaded_idx {
            Some(i) => (
                project.bundled_db_enabled.get(i).copied().unwrap_or(true),
                Some(project.bundled_dbs[i].signature_count),
                Some(project.bundled_db_hits.get(i).copied().unwrap_or(0)),
            ),
            None => (false, None, None),
        };
        tree.entry(sig.subdir.clone()).or_default().push(FlirtRowSnapshot {
            subdir: sig.subdir.clone(),
            stem: sig.stem.clone(),
            loaded_idx,
            enabled,
            sig_count,
            hits,
        });
    }

    // User-loaded sigs (via File → Load Signatures…) live outside the
    // embedded tree. Render them in their own group below the embedded
    // ones so the bundled-vs-user distinction stays visible.
    let user_rows: Vec<FlirtRowSnapshot> = project
        .user_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| FlirtRowSnapshot {
            subdir: "user".to_string(),
            stem: db.header.name.clone(),
            loaded_idx: Some(i),
            enabled: project.user_db_enabled.get(i).copied().unwrap_or(true),
            sig_count: Some(db.signature_count),
            hits: Some(project.user_db_hits.get(i).copied().unwrap_or(0)),
        })
        .collect();

    if tree.is_empty() && user_rows.is_empty() {
        ui.label("(no signature databases shipped with this build)");
        return;
    }

    let mut actions: Vec<FlirtAction> = Vec::new();

    for (subdir, rows) in &tree {
        // Loaded count in the header makes the auto-loaded subdir
        // visually distinct (everything checked) from a wholly opt-in
        // one (everything unchecked).
        let loaded = rows.iter().filter(|r| r.loaded_idx.is_some()).count();
        let header_label = format!("{subdir}  ({loaded}/{} loaded)", rows.len());
        // Default-open subdirs that have any loaded entries; collapsed
        // for fully-opt-in subdirs so the long Borland/Watcom/etc.
        // lists don't drown out the relevant ones.
        egui::CollapsingHeader::new(header_label)
            .id_salt(format!("flirt_subdir::{subdir}"))
            .default_open(loaded > 0)
            .show(ui, |ui| {
                emit_flirt_table(ui, &format!("flirt_grid::{subdir}"), rows, &mut actions);
            });
    }

    if !user_rows.is_empty() {
        egui::CollapsingHeader::new(format!("user  ({} loaded)", user_rows.len()))
            .id_salt("flirt_subdir::user")
            .default_open(true)
            .show(ui, |ui| {
                emit_flirt_table(ui, "flirt_grid::user", &user_rows, &mut actions);
            });
    }

    for action in actions {
        match action {
            FlirtAction::LoadAndEnable { subdir, stem } => {
                project.load_bundled_sig(&subdir, &stem);
            }
            FlirtAction::SetBundledEnabled { idx, enabled } => {
                project.set_bundled_db_enabled(idx, enabled);
            }
            FlirtAction::SetUserEnabled { idx, enabled } => {
                project.set_user_db_enabled(idx, enabled);
            }
        }
    }
}

fn emit_flirt_table(
    ui: &mut egui::Ui,
    grid_id: &str,
    rows: &[FlirtRowSnapshot],
    actions: &mut Vec<FlirtAction>,
) {
    egui::Grid::new(grid_id)
        .num_columns(4)
        .striped(true)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label("");
            ui.label(egui::RichText::new("Name").strong());
            ui.label(egui::RichText::new("Sigs").strong());
            ui.label(egui::RichText::new("Hits").strong());
            ui.end_row();

            for row in rows {
                let mut on = row.enabled;
                ui.checkbox(&mut on, "");
                ui.label(&row.stem);
                ui.label(match row.sig_count {
                    Some(n) => format!("{n}"),
                    None => "—".to_string(),
                });
                ui.label(match row.hits {
                    Some(n) => format!("{n}"),
                    None => "—".to_string(),
                });
                ui.end_row();

                if on == row.enabled {
                    continue;
                }
                match (row.loaded_idx, row.subdir.as_str(), on) {
                    // User-loaded row toggle.
                    (Some(idx), "user", _) => {
                        actions.push(FlirtAction::SetUserEnabled { idx, enabled: on });
                    }
                    // Already-loaded bundled row toggle.
                    (Some(idx), _, _) => {
                        actions.push(FlirtAction::SetBundledEnabled { idx, enabled: on });
                    }
                    // Unloaded bundled row checked → lazy-load.
                    (None, subdir, true) => {
                        actions.push(FlirtAction::LoadAndEnable {
                            subdir: subdir.to_string(),
                            stem: row.stem.clone(),
                        });
                    }
                    // Unloaded bundled row unchecked → no-op (was
                    // already off; nothing to do).
                    (None, _, false) => {}
                }
            }
        });
}

// ---------------------------------------------------------------------------
// Type archive section — flat table over every embedded stem
// ---------------------------------------------------------------------------

struct ArchiveRowSnapshot {
    stem: String,
    /// `Some(idx)` when parsed and present at `project.type_archives[idx]`.
    loaded_idx: Option<usize>,
    enabled: bool,
    fn_count: Option<usize>,
    hits: Option<usize>,
}

enum ArchiveAction {
    LoadAndEnable { stem: String },
    SetEnabled { idx: usize, enabled: bool },
}

/// Render the type archive section. Returns `true` if any toggle was
/// applied so the caller knows to invalidate the decompile cache.
fn render_type_archive_section(ui: &mut egui::Ui, project: &mut reghidra_core::Project) -> bool {
    ui.heading("Type archives");

    if project.available_archive_stems.is_empty() {
        ui.label("(no type archives shipped with this build)");
        return false;
    }

    let loaded_by_stem: std::collections::HashMap<&str, usize> = project
        .type_archives
        .iter()
        .enumerate()
        .map(|(i, a)| (a.name.as_str(), i))
        .collect();

    let rows: Vec<ArchiveRowSnapshot> = project
        .available_archive_stems
        .iter()
        .map(|stem| {
            let loaded_idx = loaded_by_stem.get(stem.as_str()).copied();
            let (enabled, fn_count, hits) = match loaded_idx {
                Some(i) => (
                    project.type_archive_enabled.get(i).copied().unwrap_or(true),
                    Some(project.type_archives[i].functions.len()),
                    Some(project.type_archive_hits.get(i).copied().unwrap_or(0)),
                ),
                None => (false, None, None),
            };
            ArchiveRowSnapshot {
                stem: stem.clone(),
                loaded_idx,
                enabled,
                fn_count,
                hits,
            }
        })
        .collect();

    let mut actions: Vec<ArchiveAction> = Vec::new();

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

            for row in &rows {
                let mut on = row.enabled;
                ui.checkbox(&mut on, "");
                ui.label(&row.stem);
                ui.label(match row.fn_count {
                    Some(n) => format!("{n}"),
                    None => "—".to_string(),
                });
                ui.label(match row.hits {
                    Some(n) => format!("{n}"),
                    None => "—".to_string(),
                });
                ui.end_row();

                if on == row.enabled {
                    continue;
                }
                match (row.loaded_idx, on) {
                    (Some(idx), _) => {
                        actions.push(ArchiveAction::SetEnabled { idx, enabled: on });
                    }
                    (None, true) => {
                        actions.push(ArchiveAction::LoadAndEnable {
                            stem: row.stem.clone(),
                        });
                    }
                    (None, false) => {}
                }
            }
        });

    let mut touched = false;
    for action in actions {
        match action {
            ArchiveAction::LoadAndEnable { stem } => {
                if project.load_type_archive_by_stem(&stem).is_some() {
                    touched = true;
                }
            }
            ArchiveAction::SetEnabled { idx, enabled } => {
                project.set_type_archive_enabled(idx, enabled);
                touched = true;
            }
        }
    }
    touched
}
