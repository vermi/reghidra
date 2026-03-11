use crate::app::ReghidraApp;
use egui::{RichText, Stroke, Ui};
use reghidra_core::{ControlFlowGraph, EdgeKind};

use crate::theme::Theme;

/// Render the control flow graph for the currently selected function.
pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let selected_addr = app.selected_address.unwrap_or(0);

    let func = project
        .analysis
        .function_containing(selected_addr)
        .or_else(|| project.analysis.function_at(selected_addr));

    let Some(func) = func else {
        ui.label("Select a function to view its control flow graph.");
        return;
    };

    let func_name = func.name.clone();
    let func_entry = func.entry_address;

    let Some(cfg) = project.analysis.cfgs.get(&func_entry) else {
        ui.label("No CFG available for this function.");
        return;
    };

    ui.label(
        RichText::new(format!(
            "{} -- {} blocks, {} edges",
            func_name,
            cfg.block_count(),
            cfg.edges.len()
        ))
        .strong(),
    );
    ui.separator();

    if cfg.blocks.is_empty() {
        ui.label("Empty CFG.");
        return;
    }

    let mut navigate_to = None;
    render_block_list(cfg, ui, &mut navigate_to, selected_addr, &app.theme);

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}

fn render_block_list(
    cfg: &ControlFlowGraph,
    ui: &mut Ui,
    navigate_to: &mut Option<u64>,
    selected_addr: u64,
    theme: &Theme,
) {
    let mono = egui::TextStyle::Monospace;

    egui::ScrollArea::vertical()
        .id_salt("cfg_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (&block_addr, block) in &cfg.blocks {
                let preds = cfg.preds(block_addr);
                let succs = cfg.succs(block_addr);

                let is_entry = block_addr == cfg.entry;
                let contains_selected =
                    block.instructions.iter().any(|i| i.address == selected_addr);

                // Block header
                ui.horizontal(|ui| {
                    let header_color = if is_entry {
                        theme.cfg_entry
                    } else if contains_selected {
                        theme.cfg_active
                    } else {
                        theme.cfg_block
                    };

                    let entry_marker = if is_entry { " [ENTRY]" } else { "" };
                    ui.label(
                        RichText::new(format!("Block 0x{block_addr:08x}{entry_marker}"))
                            .text_style(mono.clone())
                            .color(header_color)
                            .strong(),
                    );

                    if !preds.is_empty() {
                        let pred_str: Vec<String> =
                            preds.iter().map(|p| format!("0x{p:08x}")).collect();
                        ui.label(
                            RichText::new(format!("preds: {}", pred_str.join(", ")))
                                .text_style(mono.clone())
                                .color(theme.text_dim),
                        );
                    }
                });

                // Block body
                let frame = egui::Frame::new()
                    .stroke(Stroke::new(
                        1.0,
                        if contains_selected {
                            theme.cfg_border_active
                        } else {
                            theme.cfg_border
                        },
                    ))
                    .inner_margin(4.0)
                    .corner_radius(2.0);

                frame.show(ui, |ui| {
                    for insn in &block.instructions {
                        let is_selected = insn.address == selected_addr;
                        ui.horizontal(|ui| {
                            let addr_color = if is_selected {
                                theme.addr_selected
                            } else {
                                theme.addr_normal
                            };

                            if ui
                                .link(
                                    RichText::new(format!("0x{:08x}", insn.address))
                                        .text_style(mono.clone())
                                        .color(addr_color),
                                )
                                .clicked()
                            {
                                *navigate_to = Some(insn.address);
                            }

                            let mc = theme.mnemonic_color(&insn.mnemonic);
                            ui.label(
                                RichText::new(format!("  {:<8}", insn.mnemonic))
                                    .text_style(mono.clone())
                                    .color(mc),
                            );
                            ui.label(
                                RichText::new(&insn.operands)
                                    .text_style(mono.clone())
                                    .color(theme.text_primary),
                            );
                        });
                    }
                });

                // Show successors
                if !succs.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("  ").text_style(mono.clone()));
                        for &succ in succs {
                            let edge =
                                cfg.edges.iter().find(|e| e.from == block_addr && e.to == succ);
                            let (label, color) = match edge.map(|e| e.kind) {
                                Some(EdgeKind::ConditionalTrue) => {
                                    (format!("T -> 0x{succ:08x}"), theme.cfg_edge_true)
                                }
                                Some(EdgeKind::ConditionalFalse) => {
                                    (format!("F -> 0x{succ:08x}"), theme.cfg_edge_false)
                                }
                                _ => (format!("-> 0x{succ:08x}"), theme.cfg_edge_uncond),
                            };
                            if ui
                                .link(RichText::new(label).text_style(mono.clone()).color(color))
                                .clicked()
                            {
                                *navigate_to = Some(succ);
                            }
                            ui.add_space(8.0);
                        }
                    });
                }

                ui.add_space(8.0);
            }
        });
}
