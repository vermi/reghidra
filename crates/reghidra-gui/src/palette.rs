use egui::{Align2, Area, Color32, Frame, Id, Key, Order, RichText, Stroke, Ui};
use reghidra_core::Project;

use crate::theme::Theme;

/// An entry in the command palette results.
#[derive(Clone)]
pub struct PaletteEntry {
    pub label: String,
    pub detail: String,
    pub action: PaletteAction,
}

/// What happens when a palette entry is selected.
#[derive(Clone)]
pub enum PaletteAction {
    NavigateTo(u64),
    SwitchView(crate::app::MainView),
    ToggleTheme,
    ShowHelp,
    SaveSession,
    OpenSession,
    #[allow(dead_code)]
    GoToAddress,
}

/// State for the command palette.
pub struct CommandPalette {
    pub open: bool,
    pub query: String,
    pub selected_index: usize,
    pub entries: Vec<PaletteEntry>,
    /// When true, the text field needs focus on the next frame.
    pub needs_focus: bool,
}

impl CommandPalette {
    pub fn new() -> Self {
        Self {
            open: false,
            query: String::new(),
            selected_index: 0,
            entries: Vec::new(),
            needs_focus: false,
        }
    }

    pub fn toggle(&mut self) {
        self.open = !self.open;
        if self.open {
            self.query.clear();
            self.selected_index = 0;
            self.entries.clear();
            self.needs_focus = true;
        }
    }

    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
        self.entries.clear();
    }

    /// Rebuild the filtered entry list from the project.
    pub fn update_entries(&mut self, project: &Project) {
        let query_lower = self.query.to_lowercase();
        self.entries.clear();

        // Commands (always available)
        let commands = [
            PaletteEntry {
                label: "Toggle Dark/Light Theme".into(),
                detail: "Switch theme".into(),
                action: PaletteAction::ToggleTheme,
            },
            PaletteEntry {
                label: "View: Disassembly".into(),
                detail: "Switch to disassembly view".into(),
                action: PaletteAction::SwitchView(crate::app::MainView::Disassembly),
            },
            PaletteEntry {
                label: "View: Decompile".into(),
                detail: "Switch to decompiled view".into(),
                action: PaletteAction::SwitchView(crate::app::MainView::Decompile),
            },
            PaletteEntry {
                label: "View: Hex".into(),
                detail: "Switch to hex view".into(),
                action: PaletteAction::SwitchView(crate::app::MainView::Hex),
            },
            PaletteEntry {
                label: "View: CFG".into(),
                detail: "Switch to CFG view".into(),
                action: PaletteAction::SwitchView(crate::app::MainView::Cfg),
            },
            PaletteEntry {
                label: "View: Xrefs".into(),
                detail: "Switch to cross-references view".into(),
                action: PaletteAction::SwitchView(crate::app::MainView::Xrefs),
            },
            PaletteEntry {
                label: "View: IR".into(),
                detail: "Switch to IR view".into(),
                action: PaletteAction::SwitchView(crate::app::MainView::Ir),
            },
            PaletteEntry {
                label: "Help: Quick Start Guide".into(),
                detail: "Open help overlay (F1)".into(),
                action: PaletteAction::ShowHelp,
            },
            PaletteEntry {
                label: "Save Session".into(),
                detail: "Save annotations to file (Cmd+S)".into(),
                action: PaletteAction::SaveSession,
            },
            PaletteEntry {
                label: "Open Session".into(),
                detail: "Load a saved session file".into(),
                action: PaletteAction::OpenSession,
            },
        ];

        for cmd in &commands {
            if query_lower.is_empty() || fuzzy_match(&cmd.label, &query_lower) {
                self.entries.push(cmd.clone());
            }
        }

        // "Go to address" if query looks like hex
        let addr_query = self.query.trim().trim_start_matches("0x");
        if let Ok(addr) = u64::from_str_radix(addr_query, 16) {
            self.entries.insert(
                0,
                PaletteEntry {
                    label: format!("Go to 0x{addr:08x}"),
                    detail: "Navigate to address".into(),
                    action: PaletteAction::NavigateTo(addr),
                },
            );
        }

        // Functions
        let functions = project.functions();
        for (addr, name) in &functions {
            if query_lower.is_empty()
                || fuzzy_match(&name, &query_lower)
                || format!("0x{addr:x}").contains(&query_lower)
            {
                self.entries.push(PaletteEntry {
                    label: name.clone(),
                    detail: format!("fn @ 0x{addr:08x}"),
                    action: PaletteAction::NavigateTo(*addr),
                });
            }
        }

        // Strings (limit to 50 matches)
        let mut string_count = 0;
        for s in &project.binary.strings {
            if string_count >= 50 {
                break;
            }
            if query_lower.is_empty() || s.value.to_lowercase().contains(&query_lower) {
                let preview: String = s.value.chars().take(60).collect();
                self.entries.push(PaletteEntry {
                    label: format!("\"{preview}\""),
                    detail: format!("string @ 0x{:08x}", s.address),
                    action: PaletteAction::NavigateTo(s.address),
                });
                string_count += 1;
            }
        }

        // Cap total results
        self.entries.truncate(100);

        // Clamp selected index
        if self.selected_index >= self.entries.len() && !self.entries.is_empty() {
            self.selected_index = self.entries.len() - 1;
        }
    }

    /// Render the command palette overlay. Returns the selected action if one was chosen.
    pub fn show(&mut self, ctx: &egui::Context, theme: &Theme) -> Option<PaletteAction> {
        if !self.open {
            return None;
        }

        let mut result = None;

        // Handle keyboard navigation before rendering
        ctx.input(|i| {
            if i.key_pressed(Key::Escape) {
                self.open = false;
            }
            if i.key_pressed(Key::ArrowDown) {
                if !self.entries.is_empty() {
                    self.selected_index =
                        (self.selected_index + 1).min(self.entries.len() - 1);
                }
            }
            if i.key_pressed(Key::ArrowUp) {
                self.selected_index = self.selected_index.saturating_sub(1);
            }
            if i.key_pressed(Key::Enter) && !self.entries.is_empty() {
                result = Some(self.entries[self.selected_index].action.clone());
            }
        });

        if result.is_some() {
            self.close();
            return result;
        }

        if !self.open {
            return None;
        }

        // Dim background
        let screen_rect = ctx.screen_rect();
        let painter = ctx.layer_painter(egui::LayerId::new(
            Order::Foreground,
            Id::new("palette_bg"),
        ));
        painter.rect_filled(
            screen_rect,
            0.0,
            Color32::from_rgba_premultiplied(0, 0, 0, 120),
        );

        let palette_width = (screen_rect.width() * 0.5).min(600.0).max(350.0);

        Area::new(Id::new("command_palette"))
            .order(Order::Foreground)
            .anchor(Align2::CENTER_TOP, [0.0, 80.0])
            .show(ctx, |ui| {
                Frame::new()
                    .fill(theme.palette_bg)
                    .stroke(Stroke::new(1.0, theme.palette_border))
                    .corner_radius(8.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.set_width(palette_width);

                        // Search input
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.query)
                                .hint_text("Search functions, addresses, commands...")
                                .desired_width(palette_width - 16.0)
                                .font(egui::TextStyle::Monospace),
                        );
                        if self.needs_focus {
                            response.request_focus();
                            self.needs_focus = false;
                        }

                        ui.separator();

                        // Results
                        egui::ScrollArea::vertical()
                            .max_height(400.0)
                            .show(ui, |ui| {
                                render_entries(
                                    ui,
                                    &self.entries,
                                    self.selected_index,
                                    theme,
                                    &mut result,
                                );
                            });
                    });
            });

        if result.is_some() {
            self.close();
        }
        result
    }
}

fn render_entries(
    ui: &mut Ui,
    entries: &[PaletteEntry],
    selected_index: usize,
    theme: &Theme,
    result: &mut Option<PaletteAction>,
) {
    for (i, entry) in entries.iter().enumerate() {
        let is_selected = i == selected_index;
        let bg = if is_selected {
            theme.palette_selected_bg
        } else {
            Color32::TRANSPARENT
        };

        Frame::new()
            .fill(bg)
            .corner_radius(4.0)
            .inner_margin(4.0)
            .show(ui, |ui| {
                let resp = ui
                    .horizontal(|ui| {
                        ui.label(
                            RichText::new(&entry.label)
                                .strong()
                                .color(theme.text_primary),
                        );
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    RichText::new(&entry.detail)
                                        .color(theme.text_secondary)
                                        .small(),
                                );
                            },
                        );
                    })
                    .response;

                if resp.clicked() {
                    *result = Some(entry.action.clone());
                }
            });
    }
}

/// Simple fuzzy matching: all characters of the query appear in order in the target.
fn fuzzy_match(target: &str, query: &str) -> bool {
    let target_lower = target.to_lowercase();
    let mut target_chars = target_lower.chars();
    for qc in query.chars() {
        loop {
            match target_chars.next() {
                Some(tc) if tc == qc => break,
                Some(_) => continue,
                None => return false,
            }
        }
    }
    true
}
