use crate::app::ReghidraApp;
use egui::{RichText, Ui};

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    if project.binary.sections.is_empty() {
        ui.label("No sections to display.");
        return;
    }

    let bytes_per_row = app.hex_bytes_per_row;
    let selected_addr = app.selected_address.unwrap_or(0);
    let theme = &app.theme;

    // Collect section info before mutable borrow
    let section_info: Vec<(String, u64)> = project
        .binary
        .sections
        .iter()
        .map(|s| (s.name.clone(), s.virtual_address))
        .collect();

    let section = project
        .binary
        .section_at_va(selected_addr)
        .or_else(|| project.binary.sections.first());

    let Some(section) = section else {
        ui.label("No section data available.");
        return;
    };

    let sec_start = section.file_offset as usize;
    let sec_end = sec_start + section.file_size as usize;
    let current_sec_va = section.virtual_address;

    if sec_end > project.binary.data.len() {
        ui.label("Section data out of bounds.");
        return;
    }

    let sec_data: Vec<u8> = project.binary.data[sec_start..sec_end].to_vec();
    let base_va = current_sec_va;
    let total_rows = (sec_data.len() + bytes_per_row - 1) / bytes_per_row;
    let row_height = 18.0;
    let mono = egui::TextStyle::Monospace;

    // Section selector
    let mut nav_target: Option<u64> = None;
    ui.horizontal(|ui| {
        ui.label("Section:");
        for (name, va) in &section_info {
            let selected = *va == current_sec_va;
            if ui.selectable_label(selected, name).clicked() {
                nav_target = Some(*va);
            }
        }
    });
    if let Some(addr) = nav_target {
        app.navigate_to(addr);
        return;
    }
    ui.separator();

    // Column header
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{:<12}", "Address"))
                .text_style(mono.clone())
                .color(theme.column_header),
        );
        let mut header = String::new();
        for i in 0..bytes_per_row {
            if i > 0 && i % 8 == 0 {
                header.push(' ');
            }
            header.push_str(&format!("{i:02X} "));
        }
        ui.label(
            RichText::new(header)
                .text_style(mono.clone())
                .color(theme.column_header),
        );
        ui.label(
            RichText::new("ASCII")
                .text_style(mono.clone())
                .color(theme.column_header),
        );
    });
    ui.separator();

    let mut navigate_to = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, row_height, total_rows, |ui, row_range| {
            for row in row_range {
                let offset = row * bytes_per_row;
                let row_addr = base_va + offset as u64;
                let end = (offset + bytes_per_row).min(sec_data.len());
                let row_bytes = &sec_data[offset..end];

                ui.horizontal(|ui| {
                    let addr_text = RichText::new(format!("0x{row_addr:08x}  "))
                        .text_style(mono.clone())
                        .color(theme.addr_normal);
                    if ui.link(addr_text).clicked() {
                        navigate_to = Some(row_addr);
                    }

                    let mut hex = String::with_capacity(bytes_per_row * 3 + 4);
                    for (i, &byte) in row_bytes.iter().enumerate() {
                        if i > 0 && i % 8 == 0 {
                            hex.push(' ');
                        }
                        hex.push_str(&format!("{byte:02x} "));
                    }
                    let padding_bytes = bytes_per_row - row_bytes.len();
                    for i in 0..padding_bytes {
                        let total_i = row_bytes.len() + i;
                        if total_i > 0 && total_i % 8 == 0 {
                            hex.push(' ');
                        }
                        hex.push_str("   ");
                    }

                    ui.label(
                        RichText::new(&hex)
                            .text_style(mono.clone())
                            .color(theme.hex_bytes),
                    );

                    let ascii: String = row_bytes
                        .iter()
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    ui.label(
                        RichText::new(&ascii)
                            .text_style(mono.clone())
                            .color(theme.hex_ascii),
                    );
                });
            }
        });

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}
