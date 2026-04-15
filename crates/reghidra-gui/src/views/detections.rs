//! Detections side-panel tab.
//!
//! Shows all [`reghidra_detect::DetectionHit`]s returned by the most recent
//! `project.evaluate_detections()` run, grouped by severity in collapsing
//! headers (Malicious → Suspicious → Info).  Within each severity bucket,
//! file-scope hits are listed first (tagged `[file]`) followed by
//! function-scope hits (`0x????????  rule_name`).  Clicking a function-scope
//! row navigates to that function.  Hovering any row shows the hit's
//! description in a tooltip.

use crate::app::ReghidraApp;
use egui::Ui;
use reghidra_core::DetectionSeverity;

const DETECTIONS_ROW_HEIGHT: f32 = 18.0;

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        ui.label("No binary loaded.");
        return;
    };

    let theme = app.theme.clone();
    let results = &project.detection_results;

    let total_hits = results.file_hits.len()
        + results
            .function_hits
            .values()
            .map(|v| v.len())
            .sum::<usize>();

    ui.label(format!("{total_hits} detection hit(s)"));
    ui.separator();

    if total_hits == 0 {
        ui.label(
            egui::RichText::new("No detections fired on this binary.")
                .color(theme.text_dim),
        );
        return;
    }

    // Build flat lists per severity so we can virtualize each section.
    // Each entry is (Option<u64> = function addr, rule_name, description, severity).
    let mut malicious: Vec<(Option<u64>, String, String)> = Vec::new();
    let mut suspicious: Vec<(Option<u64>, String, String)> = Vec::new();
    let mut info: Vec<(Option<u64>, String, String)> = Vec::new();

    // File-scope hits have no address.
    for hit in &results.file_hits {
        let bucket = match hit.severity {
            DetectionSeverity::Malicious => &mut malicious,
            DetectionSeverity::Suspicious => &mut suspicious,
            DetectionSeverity::Info => &mut info,
        };
        bucket.push((None, hit.rule_name.clone(), hit.description.clone()));
    }

    // Function-scope hits.
    let mut fn_hits: Vec<(u64, &reghidra_core::DetectionHit)> = results
        .function_hits
        .iter()
        .flat_map(|(addr, hits)| hits.iter().map(move |h| (*addr, h)))
        .collect();
    // Sort by address for stable ordering.
    fn_hits.sort_by_key(|(addr, _)| *addr);
    for (addr, hit) in fn_hits {
        let bucket = match hit.severity {
            DetectionSeverity::Malicious => &mut malicious,
            DetectionSeverity::Suspicious => &mut suspicious,
            DetectionSeverity::Info => &mut info,
        };
        bucket.push((Some(addr), hit.rule_name.clone(), hit.description.clone()));
    }

    let mut navigate_to: Option<u64> = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            render_severity_section(
                ui,
                &theme,
                "Malicious",
                theme.detection_malicious,
                &malicious,
                &mut navigate_to,
            );
            render_severity_section(
                ui,
                &theme,
                "Suspicious",
                theme.detection_suspicious,
                &suspicious,
                &mut navigate_to,
            );
            render_severity_section(
                ui,
                &theme,
                "Info",
                theme.detection_info,
                &info,
                &mut navigate_to,
            );
        });

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}

fn render_severity_section(
    ui: &mut Ui,
    theme: &crate::theme::Theme,
    label: &str,
    color: egui::Color32,
    rows: &[(Option<u64>, String, String)],
    navigate_to: &mut Option<u64>,
) {
    if rows.is_empty() {
        return;
    }

    // Header with colored badge showing count.
    let mut header_job = egui::text::LayoutJob::default();
    header_job.append(
        label,
        0.0,
        egui::TextFormat {
            color: theme.text_primary,
            ..Default::default()
        },
    );
    header_job.append(
        &format!("  ({})", rows.len()),
        0.0,
        egui::TextFormat {
            color,
            font_id: egui::FontId::proportional(11.0),
            ..Default::default()
        },
    );

    egui::CollapsingHeader::new(header_job)
        .id_salt(format!("det_sev::{label}"))
        .default_open(true)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt(format!("det_scroll::{label}"))
                .auto_shrink([false, false])
                .max_height(200.0)
                .show_rows(ui, DETECTIONS_ROW_HEIGHT, rows.len(), |ui, row_range| {
                    for idx in row_range {
                        let (addr, rule_name, description) = &rows[idx];
                        let row_text = match addr {
                            Some(a) => format!("0x{a:08x}  {rule_name}"),
                            None => format!("[file]  {rule_name}"),
                        };
                        let resp = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&row_text).color(color).monospace(),
                            )
                            .sense(egui::Sense::click()),
                        );
                        if resp.clicked() {
                            if let Some(a) = addr {
                                *navigate_to = Some(*a);
                            }
                        }
                        if !description.is_empty() {
                            resp.on_hover_text(description.as_str());
                        }
                    }
                });
        });
}
