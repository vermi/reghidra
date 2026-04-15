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
use crate::theme::Theme;
use std::collections::BTreeMap;
use std::path::Path;

/// Render a section heading: smaller and less shouty than `ui.heading`,
/// with a subtle separator beneath. Used for both "FLIRT signature
/// databases" and "Type archives" so they read as siblings instead of
/// competing for attention.
fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.add(
        egui::Label::new(
            egui::RichText::new(text)
                .size(15.0)
                .strong()
                .color(ui.visuals().widgets.active.fg_stroke.color),
        )
        .selectable(false),
    );
    ui.add_space(2.0);
    ui.separator();
    ui.add_space(4.0);
}

/// Build a `CollapsingHeader` whose label has the title in regular
/// weight followed by a colored loaded-count badge, so the eye lands
/// on "is anything loaded here" without re-reading the count.
fn tree_header(theme: &Theme, title: &str, loaded: usize, total: usize) -> egui::WidgetText {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        title,
        0.0,
        egui::TextFormat {
            color: theme.text_primary,
            ..Default::default()
        },
    );
    job.append(
        &format!("  ({loaded} / {total})"),
        0.0,
        egui::TextFormat {
            color: if loaded > 0 {
                theme.func_header_sig
            } else {
                theme.text_dim
            },
            font_id: egui::FontId::proportional(11.0),
            ..Default::default()
        },
    );
    job.into()
}

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
    let theme = app.theme.clone();

    egui::Window::new(
        egui::RichText::new("Loaded Data Sources")
            .strong()
            .color(theme.text_primary),
    )
    .open(&mut open)
    .resizable(true)
    .default_width(720.0)
    .default_height(560.0)
    .min_width(520.0)
    .frame(
        egui::Frame::window(&ctx.style())
            .inner_margin(egui::Margin::symmetric(14, 12))
            .corner_radius(egui::CornerRadius::same(8)),
    )
    .show(ctx, |ui| {
        let Some(project) = app.project.as_mut() else {
            ui.label("No binary loaded.");
            return;
        };

        ui.add(
            egui::Label::new(
                egui::RichText::new(
                    "Every signature db and type archive shipped with reghidra. \
                     Auto-loaded entries for this binary start checked; \
                     toggling an unchecked one lazy-loads it.",
                )
                .small()
                .color(theme.text_secondary),
            )
            .wrap(),
        );
        ui.add_space(10.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                render_flirt_section(ui, &theme, project);
                ui.add_space(14.0);
                if render_type_archive_section(ui, &theme, project) {
                    force_decompile_invalidate = true;
                }
                ui.add_space(14.0);
                render_detection_rules_section(ui, &theme, project);
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
        // The disasm view's minimap markers depend on which archives
        // are currently enabled (type-only / both stripes), so the
        // cached display list is stale too.
        app.disasm_lines_cache = None;
        app.disasm_display_generation += 1;
    }
}

// ---------------------------------------------------------------------------
// FLIRT section — tree grouped by `signatures/<format>/<arch>/<bits>` subdir
// ---------------------------------------------------------------------------

/// Snapshot of one row in the FLIRT tree. Built up front so we can
/// mutate `project` for toggle actions without fighting the borrow
/// checker on the iterator state.
#[derive(Clone)]
struct FlirtRowSnapshot {
    subdir: String,
    stem: String,
    /// Friendly library name from the .sig header, e.g. "Visual Studio
    /// 2010 Professional". `None` only when the header parse failed at
    /// enumeration time, in which case the row falls back to `stem`.
    library_name: Option<String>,
    /// `Some(idx)` when this sig is currently parsed and lives at
    /// `project.bundled_dbs[idx]`. `None` when only the embedded `.sig`
    /// file is known and clicking the row will lazy-load it.
    loaded_idx: Option<usize>,
    enabled: bool,
    sig_count: Option<usize>,
    hits: Option<usize>,
    /// Mirrors `AvailableSig::is_legacy` — true for Borland/Watcom/
    /// Digital Mars/old MFC/VisualAge/etc. sigs that ship in the
    /// embedded tree but don't auto-load. The panel partitions each
    /// leaf into modern rows (shown directly) and a "Legacy
    /// toolchains" subgroup so the default view isn't dominated by
    /// a wall of 1990s compilers. User sigs are always considered
    /// non-legacy.
    is_legacy: bool,
}

/// Action requested by a single click in the FLIRT tree. Drained after
/// the immutable iteration finishes.
enum FlirtAction {
    LoadAndEnable { subdir: String, stem: String },
    SetBundledEnabled { idx: usize, enabled: bool },
    SetUserEnabled { idx: usize, enabled: bool },
}

/// Three-level nested tree of bundled FLIRT sigs:
///   `format` (`pe`/`elf`) → `arch` (`x86`/`arm`/`mips`/`sh`) →
///   `bits` (`32`/`64`) → leaves (sig rows).
/// `BTreeMap` at every level so display order is deterministic
/// (alphabetical) without an extra sort step.
type FlirtTree = BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<FlirtRowSnapshot>>>>;

fn render_flirt_section(
    ui: &mut egui::Ui,
    theme: &Theme,
    project: &mut reghidra_core::Project,
) {
    section_heading(ui, "FLIRT signature databases");

    // Join key is the (subdir, stem) PAIR, not just the stem — the
    // same stem ships under multiple arch dirs (e.g. `VisualStudio2017`
    // exists in `pe/x86/32`, `pe/arm/32`, `pe/arm/64`) and they must
    // be addressable independently or unchecking the ARM 32 row would
    // also disable the ARM 64 and x86 32 rows. Bundled dbs encode
    // both halves in `source_path` as `bundled:<subdir>/<stem>`.
    let loaded_by_key: std::collections::HashMap<(String, String), usize> = project
        .bundled_dbs
        .iter()
        .enumerate()
        .filter_map(|(i, db)| {
            let s = db.source_path.to_str()?.strip_prefix("bundled:")?;
            let (subdir, stem) = s.rsplit_once('/')?;
            Some(((subdir.to_string(), stem.to_string()), i))
        })
        .collect();

    // Walk every available sig and bucket into the 3-level tree.
    // `subdir` looks like `pe/x86/32` or `elf/arm/64`; we split on
    // `/` and treat any non-3-component path as a single fallback
    // bucket so a future signatures/ layout change doesn't lose rows.
    let mut tree: FlirtTree = BTreeMap::new();
    let mut orphans: Vec<FlirtRowSnapshot> = Vec::new();
    for sig in &project.available_bundled_sigs {
        let loaded_idx = loaded_by_key
            .get(&(sig.subdir.clone(), sig.stem.clone()))
            .copied();
        let (enabled, sig_count, hits) = match loaded_idx {
            Some(i) => (
                project.bundled_db_enabled.get(i).copied().unwrap_or(true),
                Some(project.bundled_dbs[i].signature_count),
                Some(project.bundled_db_hits.get(i).copied().unwrap_or(0)),
            ),
            // Even when unloaded the header tells us the function count.
            None => (false, sig.n_functions.map(|n| n as usize), None),
        };
        let row = FlirtRowSnapshot {
            subdir: sig.subdir.clone(),
            stem: sig.stem.clone(),
            library_name: sig.library_name.clone(),
            loaded_idx,
            enabled,
            sig_count,
            hits,
            is_legacy: sig.is_legacy,
        };
        let parts: Vec<&str> = sig.subdir.split('/').collect();
        match parts.as_slice() {
            [format, arch, bits] => {
                tree.entry((*format).to_string())
                    .or_default()
                    .entry((*arch).to_string())
                    .or_default()
                    .entry((*bits).to_string())
                    .or_default()
                    .push(row);
            }
            _ => orphans.push(row),
        }
    }

    let user_rows: Vec<FlirtRowSnapshot> = project
        .user_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| FlirtRowSnapshot {
            subdir: "user".to_string(),
            stem: db
                .source_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(db.header.name.as_str())
                .to_string(),
            library_name: Some(db.header.name.clone()),
            loaded_idx: Some(i),
            enabled: project.user_db_enabled.get(i).copied().unwrap_or(true),
            sig_count: Some(db.signature_count),
            hits: Some(project.user_db_hits.get(i).copied().unwrap_or(0)),
            is_legacy: false,
        })
        .collect();

    if tree.is_empty() && user_rows.is_empty() && orphans.is_empty() {
        ui.label("(no signature databases shipped with this build)");
        return;
    }

    // Pre-measure the widest name + numeric cells across every row in
    // every leaf so each leaf's grid uses the SAME column widths. Without
    // this, each `egui::Grid` sizes its columns to its own content and
    // adjacent leaves end up with mis-aligned columns ("32-bit" vs
    // "64-bit" leaves drift by 20+ pixels).
    let all_rows = tree
        .values()
        .flat_map(|a| a.values())
        .flat_map(|b| b.values())
        .flat_map(|rows| rows.iter())
        .chain(orphans.iter())
        .chain(user_rows.iter());
    let widths = measure_flirt_widths(ui, all_rows);

    let mut actions: Vec<FlirtAction> = Vec::new();

    for (format, arches) in &tree {
        let format_loaded: usize = arches
            .values()
            .flat_map(|a| a.values())
            .flat_map(|b| b.iter())
            .filter(|r| r.loaded_idx.is_some())
            .count();
        let format_total: usize = arches
            .values()
            .flat_map(|a| a.values())
            .map(|b| b.len())
            .sum();
        // Default-open the format branch if anything inside is loaded
        // — that's almost always true for the binary's own format and
        // false for the others, which is the right starting state.
        egui::CollapsingHeader::new(tree_header(theme, format, format_loaded, format_total))
            .id_salt(format!("flirt_fmt::{format}"))
            .default_open(format_loaded > 0)
            .show(ui, |ui| {
                for (arch, bitsmap) in arches {
                    let arch_loaded: usize = bitsmap
                        .values()
                        .flat_map(|b| b.iter())
                        .filter(|r| r.loaded_idx.is_some())
                        .count();
                    let arch_total: usize = bitsmap.values().map(|b| b.len()).sum();
                    egui::CollapsingHeader::new(tree_header(
                        theme, arch, arch_loaded, arch_total,
                    ))
                    .id_salt(format!("flirt_arch::{format}/{arch}"))
                    .default_open(arch_loaded > 0)
                    .show(ui, |ui| {
                        for (bits, rows) in bitsmap {
                            let bits_loaded =
                                rows.iter().filter(|r| r.loaded_idx.is_some()).count();
                            egui::CollapsingHeader::new(tree_header(
                                theme,
                                &format!("{bits}-bit"),
                                bits_loaded,
                                rows.len(),
                            ))
                            .id_salt(format!("flirt_bits::{format}/{arch}/{bits}"))
                            .default_open(bits_loaded > 0)
                            .show(ui, |ui| {
                                // Partition the leaf into modern and
                                // legacy rows. Modern rows render
                                // directly inline; legacy rows (pre-
                                // 2010 toolchains: Borland/Watcom/
                                // Digital Mars/old MFC/etc.) get
                                // their own nested collapsing header
                                // that defaults closed unless the
                                // user has opted into something
                                // inside it. Keeps the default view
                                // focused on sigs that actually
                                // produce hits on modern targets.
                                let (modern_rows, legacy_rows): (Vec<_>, Vec<_>) =
                                    rows.iter().partition(|r| !r.is_legacy);
                                if !modern_rows.is_empty() {
                                    let modern_owned: Vec<FlirtRowSnapshot> =
                                        modern_rows.into_iter().cloned().collect();
                                    emit_flirt_table(
                                        ui,
                                        theme,
                                        &format!("flirt_grid::{format}/{arch}/{bits}"),
                                        &modern_owned,
                                        &widths,
                                        &mut actions,
                                    );
                                }
                                if !legacy_rows.is_empty() {
                                    let legacy_loaded = legacy_rows
                                        .iter()
                                        .filter(|r| r.loaded_idx.is_some())
                                        .count();
                                    egui::CollapsingHeader::new(tree_header(
                                        theme,
                                        "Legacy toolchains",
                                        legacy_loaded,
                                        legacy_rows.len(),
                                    ))
                                    .id_salt(format!(
                                        "flirt_legacy::{format}/{arch}/{bits}"
                                    ))
                                    .default_open(legacy_loaded > 0)
                                    .show(ui, |ui| {
                                        let legacy_owned: Vec<FlirtRowSnapshot> =
                                            legacy_rows.into_iter().cloned().collect();
                                        emit_flirt_table(
                                            ui,
                                            theme,
                                            &format!(
                                                "flirt_grid_legacy::{format}/{arch}/{bits}"
                                            ),
                                            &legacy_owned,
                                            &widths,
                                            &mut actions,
                                        );
                                    });
                                }
                            });
                        }
                    });
                }
            });
    }

    if !orphans.is_empty() {
        egui::CollapsingHeader::new(tree_header(theme, "(other)", 0, orphans.len()))
            .id_salt("flirt_fmt::orphans")
            .default_open(false)
            .show(ui, |ui| {
                emit_flirt_table(
                    ui,
                    theme,
                    "flirt_grid::orphans",
                    &orphans,
                    &widths,
                    &mut actions,
                );
            });
    }

    if !user_rows.is_empty() {
        let user_loaded = user_rows.iter().filter(|r| r.enabled).count();
        egui::CollapsingHeader::new(tree_header(theme, "user", user_loaded, user_rows.len()))
            .id_salt("flirt_fmt::user")
            .default_open(true)
            .show(ui, |ui| {
                emit_flirt_table(
                ui,
                theme,
                "flirt_grid::user",
                &user_rows,
                &widths,
                &mut actions,
            );
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

/// Pre-measured column widths shared across every FLIRT leaf so the
/// `emit_flirt_table` calls in different leaves render with identical
/// column boundaries. Without this, every leaf's `egui::Grid` would
/// independently size its columns to its own content and the 32-bit
/// vs 64-bit (vs other) leaves would visibly drift.
struct FlirtColWidths {
    name: f32,
    sigs: f32,
    hits: f32,
}

/// Walk every FLIRT row across every leaf, lay out each cell's text
/// using the current font, and return the max width for the variable
/// columns. The checkbox column is left to its natural size since
/// every checkbox is identical.
fn measure_flirt_widths<'a, I>(ui: &egui::Ui, rows: I) -> FlirtColWidths
where
    I: IntoIterator<Item = &'a FlirtRowSnapshot>,
{
    let mut name = 0.0_f32;
    let mut sigs = 0.0_f32;
    let mut hits = 0.0_f32;
    let body_font = egui::TextStyle::Body.resolve(ui.style());
    let mono_font = egui::FontId::monospace(11.0);
    ui.fonts(|fonts| {
        for row in rows {
            let display_name = row
                .library_name
                .as_deref()
                .filter(|n| !n.is_empty())
                .unwrap_or(&row.stem);
            let mut row_name_w = fonts
                .layout_no_wrap(
                    display_name.to_string(),
                    body_font.clone(),
                    egui::Color32::WHITE,
                )
                .size()
                .x;
            if row.library_name.as_deref().is_some_and(|n| n != row.stem) {
                row_name_w += fonts
                    .layout_no_wrap(
                        format!("  {}", row.stem),
                        mono_font.clone(),
                        egui::Color32::WHITE,
                    )
                    .size()
                    .x;
            }
            name = name.max(row_name_w);

            let sig_text = match row.sig_count {
                None => "—".to_string(),
                Some(n) => n.to_string(),
            };
            sigs = sigs.max(
                fonts
                    .layout_no_wrap(sig_text, mono_font.clone(), egui::Color32::WHITE)
                    .size()
                    .x,
            );
            let hit_text = match row.hits {
                None => "—".to_string(),
                Some(n) => n.to_string(),
            };
            hits = hits.max(
                fonts
                    .layout_no_wrap(hit_text, mono_font.clone(), egui::Color32::WHITE)
                    .size()
                    .x,
            );
        }
    });
    // Sensible floors so an all-empty leaf doesn't collapse the column
    // away — and a small breathing pad on each side.
    FlirtColWidths {
        name: name.max(160.0) + 8.0,
        sigs: sigs.max(36.0) + 8.0,
        hits: hits.max(28.0) + 8.0,
    }
}

/// Render a leaf table of FLIRT rows. No per-leaf column header — at
/// 3 levels deep the rows speak for themselves and a header on every
/// leaf adds noise without adding information. Numeric columns are
/// monospace; the row name dims when unloaded so the eye finds the
/// active sigs immediately. Column widths come from the shared
/// `widths` snapshot so leaves line up vertically.
fn emit_flirt_table(
    ui: &mut egui::Ui,
    theme: &Theme,
    grid_id: &str,
    rows: &[FlirtRowSnapshot],
    widths: &FlirtColWidths,
    actions: &mut Vec<FlirtAction>,
) {
    egui::Grid::new(grid_id)
        .num_columns(4)
        .striped(true)
        .spacing([14.0, 6.0])
        .min_col_width(0.0)
        .show(ui, |ui| {
            for row in rows {
                let mut on = row.enabled;
                ui.checkbox(&mut on, "");

                // Friendly library name from the .sig header takes the
                // foreground; the file stem follows in dim secondary
                // color so the user can still cross-reference filenames
                // without the ugly `vc32_14` shouting in the main column.
                let primary_color = if row.loaded_idx.is_some() {
                    theme.text_primary
                } else {
                    theme.text_dim
                };
                let mut job = egui::text::LayoutJob::default();
                let display_name = row
                    .library_name
                    .as_deref()
                    .filter(|n| !n.is_empty())
                    .unwrap_or(&row.stem);
                job.append(
                    display_name,
                    0.0,
                    egui::TextFormat {
                        color: primary_color,
                        ..Default::default()
                    },
                );
                if row.library_name.as_deref().is_some_and(|n| n != row.stem) {
                    job.append(
                        &format!("  {}", row.stem),
                        0.0,
                        egui::TextFormat {
                            color: theme.text_dim,
                            font_id: egui::FontId::monospace(11.0),
                            ..Default::default()
                        },
                    );
                }
                // Each cell gets `set_width` (both min and max) so the
                // Grid measures it at exactly the shared column width
                // — `set_min_width` alone is a floor, and a `right_to_left`
                // sub-layout would otherwise grab `available_width()`
                // from the ScrollArea and slip under the scrollbar.
                ui.scope(|ui| {
                    ui.set_width(widths.name);
                    ui.add(egui::Label::new(job).selectable(false));
                });

                ui.scope(|ui| {
                    ui.set_width(widths.sigs);
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            metric_cell(ui, theme, row.sig_count, row.loaded_idx.is_some());
                        },
                    );
                });
                ui.scope(|ui| {
                    ui.set_width(widths.hits);
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            metric_cell(ui, theme, row.hits, row.hits.is_some_and(|h| h > 0));
                        },
                    );
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
                    // Unloaded bundled row unchecked → no-op.
                    (None, _, false) => {}
                }
            }
        });
}

/// Monospace numeric cell. `None` renders as a dim em-dash; `Some(0)`
/// is dim; positive values use the foreground text color (or accent if
/// `accent` is true) so non-zero hits stand out at a glance.
///
/// Intentionally NOT wrapped in `Layout::right_to_left` — that helper
/// requests `ui.available_width()` which makes the trailing grid column
/// expand to fill the panel and slip behind the scroll bar. Plain
/// monospace digits are right-edge-stable enough at the widths we hit.
fn metric_cell(ui: &mut egui::Ui, theme: &Theme, value: Option<usize>, accent: bool) {
    let (text, color) = match value {
        None => ("—".to_string(), theme.text_dim),
        Some(0) => ("0".to_string(), theme.text_dim),
        Some(n) => (
            n.to_string(),
            if accent {
                theme.func_header_sig
            } else {
                theme.text_primary
            },
        ),
    };
    ui.add(
        egui::Label::new(egui::RichText::new(text).monospace().color(color))
            .selectable(false),
    );
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
fn render_type_archive_section(
    ui: &mut egui::Ui,
    theme: &Theme,
    project: &mut reghidra_core::Project,
) -> bool {
    section_heading(ui, "Type archives");

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
        .spacing([14.0, 6.0])
        .min_col_width(0.0)
        .show(ui, |ui| {
            for row in &rows {
                let mut on = row.enabled;
                ui.checkbox(&mut on, "");

                let name_color = if row.loaded_idx.is_some() {
                    theme.text_primary
                } else {
                    theme.text_dim
                };
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&row.stem).color(name_color),
                    )
                    .selectable(false),
                );

                metric_cell(ui, theme, row.fn_count, row.loaded_idx.is_some());
                metric_cell(ui, theme, row.hits, row.hits.is_some_and(|h| h > 0));
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

// ---------------------------------------------------------------------------
// Detection Rules section
// ---------------------------------------------------------------------------

enum RuleAction {
    SetEnabled { source_path: String, enabled: bool },
    LoadBundled { subdir: String, stem: String },
    LoadUser { path: std::path::PathBuf },
}

fn render_detection_rules_section(
    ui: &mut egui::Ui,
    theme: &Theme,
    project: &mut reghidra_core::Project,
) {
    section_heading(ui, "Detection Rules");

    // Snapshot loaded rule files to avoid borrow-checker conflicts during Grid.
    struct RuleRowSnapshot {
        source_path: String,
        enabled: bool,
        rule_count: usize,
        hit_count: usize,
        has_errors: bool,
        error_text: String,
    }

    let rows: Vec<RuleRowSnapshot> = project
        .loaded_rule_files
        .iter()
        .map(|rf| {
            let hit_count = project
                .detection_results
                .per_rule_file_counts
                .get(&rf.source_path)
                .copied()
                .unwrap_or(0);
            let error_text = rf.parse_errors.join("\n");
            RuleRowSnapshot {
                source_path: rf.source_path.clone(),
                enabled: rf.enabled,
                rule_count: rf.rules.len(),
                hit_count,
                has_errors: !rf.parse_errors.is_empty(),
                error_text,
            }
        })
        .collect();

    // Enumerate available but not yet loaded bundled rule files.
    let loaded_paths: std::collections::HashSet<&str> = project
        .loaded_rule_files
        .iter()
        .map(|rf| rf.source_path.as_str())
        .collect();

    // Group available by subdir for the nested "Load bundled…" tree.
    let mut available_by_subdir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rf in &project.available_bundled_rulefiles {
        let bundled_path = format!("bundled:{}/{}", rf.subdir, rf.stem);
        if !loaded_paths.contains(bundled_path.as_str()) {
            available_by_subdir
                .entry(rf.subdir.clone())
                .or_default()
                .push(rf.stem.clone());
        }
    }

    let mut actions: Vec<RuleAction> = Vec::new();

    if rows.is_empty() {
        ui.label(egui::RichText::new("No rule files loaded.").color(theme.text_dim));
    } else {
        egui::Grid::new("detection_rules_table")
            .num_columns(5)
            .striped(true)
            .spacing([14.0, 6.0])
            .min_col_width(0.0)
            .show(ui, |ui| {
                for row in &rows {
                    let mut on = row.enabled;
                    ui.checkbox(&mut on, "");

                    let name_color = if row.enabled {
                        theme.text_primary
                    } else {
                        theme.text_dim
                    };
                    // Display just the final path component as the name.
                    let display_name = row
                        .source_path
                        .rsplit_once('/')
                        .or_else(|| row.source_path.rsplit_once('\\'))
                        .map(|(_, f)| f)
                        .unwrap_or(row.source_path.as_str());
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(display_name).color(name_color),
                        )
                        .selectable(false),
                    );

                    metric_cell(ui, theme, Some(row.rule_count), true);
                    metric_cell(
                        ui,
                        theme,
                        Some(row.hit_count),
                        row.hit_count > 0,
                    );

                    // Parse-error warning icon.
                    if row.has_errors {
                        let warn = ui.add(
                            egui::Label::new(
                                egui::RichText::new("⚠")
                                    .color(theme.detection_suspicious),
                            )
                            .sense(egui::Sense::hover()),
                        );
                        warn.on_hover_text(&row.error_text);
                    } else {
                        ui.label("");
                    }

                    ui.end_row();

                    if on != row.enabled {
                        actions.push(RuleAction::SetEnabled {
                            source_path: row.source_path.clone(),
                            enabled: on,
                        });
                    }
                }
            });
    }

    ui.add_space(8.0);

    // "Load bundled…" expandable section.
    if !available_by_subdir.is_empty() {
        let available_count: usize = available_by_subdir.values().map(|v| v.len()).sum();
        egui::CollapsingHeader::new(tree_header(
            theme,
            "Load bundled rules",
            0,
            available_count,
        ))
        .id_salt("det_bundled_header")
        .default_open(false)
        .show(ui, |ui| {
            for (subdir, stems) in &available_by_subdir {
                egui::CollapsingHeader::new(
                    egui::RichText::new(subdir).color(theme.text_primary),
                )
                .id_salt(format!("det_bundled::{subdir}"))
                .default_open(false)
                .show(ui, |ui| {
                    for stem in stems {
                        if ui
                            .add(
                                egui::Label::new(
                                    egui::RichText::new(stem).color(theme.text_secondary),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .clicked()
                        {
                            actions.push(RuleAction::LoadBundled {
                                subdir: subdir.clone(),
                                stem: stem.clone(),
                            });
                        }
                    }
                });
            }
        });
    }

    // "Load user file…" button.
    if ui.button("Load user rule file…").clicked() {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Load Detection Rule File")
            .add_filter("YAML rule files", &["yml", "yaml"])
            .pick_file()
        {
            actions.push(RuleAction::LoadUser { path });
        }
    }

    // Drain actions after the immutable Grid/CollapsingHeader borrows.
    for action in actions {
        match action {
            RuleAction::SetEnabled { source_path, enabled } => {
                project.set_rule_file_enabled(&source_path, enabled);
            }
            RuleAction::LoadBundled { subdir, stem } => {
                let _ = project.load_bundled_rule_file(&subdir, &stem);
            }
            RuleAction::LoadUser { path } => {
                let _ = project.load_user_rule_file(Path::new(&path));
            }
        }
    }
}
