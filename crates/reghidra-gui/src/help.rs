use egui::{Align2, Area, Id, Key, Order, RichText, Stroke};

use crate::theme::Theme;

/// Which help tab is currently visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelpTab {
    QuickStart,
    Keyboard,
    Views,
    Workflow,
}

/// State for the in-app help overlay.
pub struct HelpOverlay {
    pub open: bool,
    tab: HelpTab,
}

impl HelpOverlay {
    pub fn new() -> Self {
        Self {
            open: false,
            tab: HelpTab::QuickStart,
        }
    }

    pub fn toggle(&mut self) {
        self.open = !self.open;
        if self.open {
            self.tab = HelpTab::QuickStart;
        }
    }

    /// Render the help overlay. Returns true if the overlay consumed input (is open).
    pub fn show(&mut self, ctx: &egui::Context, theme: &Theme) -> bool {
        if !self.open {
            return false;
        }

        // Handle close
        ctx.input(|i| {
            if i.key_pressed(Key::Escape) || i.key_pressed(Key::F1) {
                self.open = false;
            }
        });

        if !self.open {
            return false;
        }

        // Dim background
        let screen_rect = ctx.screen_rect();
        let painter = ctx.layer_painter(egui::LayerId::new(
            Order::Foreground,
            Id::new("help_bg"),
        ));
        painter.rect_filled(
            screen_rect,
            0.0,
            egui::Color32::from_rgba_premultiplied(0, 0, 0, 140),
        );

        let panel_width = (screen_rect.width() * 0.65).min(750.0).max(500.0);
        let panel_height = (screen_rect.height() * 0.75).min(600.0).max(400.0);

        Area::new(Id::new("help_overlay"))
            .order(Order::Foreground)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(theme.palette_bg)
                    .stroke(Stroke::new(1.0, theme.palette_border))
                    .corner_radius(8.0)
                    .inner_margin(16.0)
                    .show(ui, |ui| {
                        ui.set_width(panel_width);
                        ui.set_max_height(panel_height);

                        // Header
                        ui.horizontal(|ui| {
                            ui.heading(
                                RichText::new("Reghidra Help")
                                    .strong()
                                    .color(theme.func_header),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Close (Esc)").clicked() {
                                        self.open = false;
                                    }
                                },
                            );
                        });
                        ui.separator();

                        // Tabs
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.tab, HelpTab::QuickStart, "Quick Start");
                            ui.selectable_value(&mut self.tab, HelpTab::Keyboard, "Keyboard");
                            ui.selectable_value(&mut self.tab, HelpTab::Views, "Views");
                            ui.selectable_value(&mut self.tab, HelpTab::Workflow, "Workflow");
                        });
                        ui.separator();

                        // Content
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| match self.tab {
                                HelpTab::QuickStart => render_quickstart(ui, theme),
                                HelpTab::Keyboard => render_keyboard(ui, theme),
                                HelpTab::Views => render_views(ui, theme),
                                HelpTab::Workflow => render_workflow(ui, theme),
                            });
                    });
            });

        true
    }
}

fn section(ui: &mut egui::Ui, theme: &Theme, title: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(title).strong().size(15.0).color(theme.func_header));
    ui.add_space(2.0);
}

fn key_row(ui: &mut egui::Ui, theme: &Theme, key: &str, desc: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{key:>18}"))
                .monospace()
                .color(theme.addr_normal),
        );
        ui.label(RichText::new(format!("  {desc}")).color(theme.text_primary));
    });
}

fn body(ui: &mut egui::Ui, theme: &Theme, text: &str) {
    ui.label(RichText::new(text).color(theme.text_secondary));
}

fn render_quickstart(ui: &mut egui::Ui, theme: &Theme) {
    section(ui, theme, "Welcome to Reghidra");
    body(
        ui,
        theme,
        "Reghidra is a reverse engineering framework for analyzing compiled binaries. \
         It supports ELF, PE, and Mach-O formats on x86_64 and ARM64 architectures.",
    );

    section(ui, theme, "Getting Started");
    body(ui, theme, "1. Open a binary with Cmd+O (or File > Open)");
    body(ui, theme, "2. The disassembly view loads automatically at the entry point");
    body(ui, theme, "3. Browse functions in the left sidebar (Fn tab)");
    body(ui, theme, "4. Click any function or address to navigate there");
    body(ui, theme, "5. Use number keys 1-6 to switch between views");

    section(ui, theme, "Essential Shortcuts");
    key_row(ui, theme, "Cmd+O", "Open a binary file");
    key_row(ui, theme, "Cmd+K", "Command palette (fuzzy search everything)");
    key_row(ui, theme, "j / k", "Navigate next/prev instruction");
    key_row(ui, theme, "n / N", "Navigate next/prev function");
    key_row(ui, theme, "1-6", "Switch views (Disasm, Decomp, Hex, CFG, Xrefs, IR)");
    key_row(ui, theme, "Space", "Toggle split view");
    key_row(ui, theme, "F1 or ?", "Toggle this help overlay");

    section(ui, theme, "Quick Tips");
    body(
        ui,
        theme,
        "- Use the command palette (Cmd+K) to jump to any function, address, or string",
    );
    body(
        ui,
        theme,
        "- Press Space to split the view and see disassembly + decompilation side by side",
    );
    body(
        ui,
        theme,
        "- Press ; on any instruction to add a comment, r to rename a function",
    );
    body(
        ui,
        theme,
        "- Alt+Left/Right to go back/forward in navigation history",
    );
    body(
        ui,
        theme,
        "- Use the Filter box in the sidebar to search functions, strings, and symbols",
    );
}

fn render_keyboard(ui: &mut egui::Ui, theme: &Theme) {
    section(ui, theme, "Global Shortcuts");
    key_row(ui, theme, "Cmd+O", "Open binary file");
    key_row(ui, theme, "Cmd+K", "Command palette");
    key_row(ui, theme, "Cmd+Z", "Undo");
    key_row(ui, theme, "Cmd+Shift+Z", "Redo");
    key_row(ui, theme, "Cmd+B", "Toggle bookmark");
    key_row(ui, theme, "Cmd+S", "Save session");
    key_row(ui, theme, "Cmd+Shift+S", "Save session as...");
    key_row(ui, theme, "Cmd+D", "Toggle dark/light theme");
    key_row(ui, theme, "Alt+Left", "Navigate back");
    key_row(ui, theme, "Alt+Right", "Navigate forward");
    key_row(ui, theme, "F1 or ?", "Toggle help");

    section(ui, theme, "Vim-style Navigation");
    body(
        ui,
        theme,
        "These keys work when no text field or modal is focused.",
    );
    ui.add_space(4.0);
    key_row(ui, theme, "j", "Next instruction");
    key_row(ui, theme, "k", "Previous instruction");
    key_row(ui, theme, "n", "Next function");
    key_row(ui, theme, "N (Shift+n)", "Previous function");
    key_row(ui, theme, "gg", "Go to first instruction");
    key_row(ui, theme, "G (Shift+g)", "Go to last instruction");

    section(ui, theme, "Views & Layout");
    key_row(ui, theme, "1", "Disassembly view");
    key_row(ui, theme, "2", "Decompile view");
    key_row(ui, theme, "3", "Hex view");
    key_row(ui, theme, "4", "Control flow graph");
    key_row(ui, theme, "5", "Cross-references");
    key_row(ui, theme, "6", "IR (intermediate representation)");
    key_row(ui, theme, "Space", "Toggle split view");

    section(ui, theme, "Annotations");
    key_row(ui, theme, ";", "Add/edit comment at current address");
    key_row(ui, theme, "r", "Rename function at current address");
    key_row(ui, theme, "x", "Switch to cross-references view");
    key_row(ui, theme, "d", "Switch to decompile view");
}

fn render_views(ui: &mut egui::Ui, theme: &Theme) {
    section(ui, theme, "Disassembly (1)");
    body(
        ui,
        theme,
        "Shows the raw disassembled instructions with addresses, bytes, and mnemonics. \
         Function headers appear in yellow with xref counts. Inline annotations show \
         call targets and string references. Comments and bookmarks are displayed inline.",
    );

    section(ui, theme, "Decompile (2)");
    body(
        ui,
        theme,
        "Displays decompiled C-like pseudocode for the function containing the selected \
         address. Control flow is structured into if/else/while statements where possible, \
         with goto as a fallback. Color-coded by statement type.",
    );

    section(ui, theme, "Hex (3)");
    body(
        ui,
        theme,
        "A hex dump view showing raw binary data organized by section. Click section \
         tabs at the top to switch. Shows 16 bytes per row with an ASCII preview column.",
    );

    section(ui, theme, "Control Flow Graph (4)");
    body(
        ui,
        theme,
        "Displays the basic block structure of the current function. Each block shows \
         its instructions and successor edges. Edge colors indicate branch type: \
         green for true, red for false, gray for unconditional.",
    );

    section(ui, theme, "Cross-References (5)");
    body(
        ui,
        theme,
        "Shows all cross-references to and from the selected address. Lists call sites, \
         jump targets, data reads/writes, and string references. Click any address to \
         navigate there.",
    );

    section(ui, theme, "IR — Intermediate Representation (6)");
    body(
        ui,
        theme,
        "Shows the lifted intermediate representation for the current function. IR ops \
         are color-coded by category (data movement, arithmetic, comparison, control flow). \
         Useful for understanding how the decompiler interprets machine code.",
    );

    section(ui, theme, "Sidebar Panels");
    body(ui, theme, "Fn  — List of detected functions (symbol-based and heuristic)");
    body(ui, theme, "Sym — All symbols from the binary's symbol table");
    body(ui, theme, "Imp — Imported functions and libraries");
    body(ui, theme, "Exp — Exported symbols");
    body(ui, theme, "Sec — Binary sections with permissions and sizes");
    body(ui, theme, "Str — Detected strings with addresses");
}

fn render_workflow(ui: &mut egui::Ui, theme: &Theme) {
    section(ui, theme, "Typical Analysis Workflow");
    body(ui, theme, "1. Open a binary (Cmd+O) — Reghidra auto-detects the format");
    body(ui, theme, "2. Browse the function list in the sidebar to find interesting targets");
    body(ui, theme, "3. Use the command palette (Cmd+K) to search by name or address");
    body(ui, theme, "4. Read the disassembly, then press 2 or d for decompiled output");
    body(ui, theme, "5. Press Space to see both views side by side");
    body(ui, theme, "6. Use x to check cross-references and trace call chains");
    body(ui, theme, "7. Add comments (;) and rename functions (r) as you go");
    body(ui, theme, "8. Bookmark interesting addresses with Cmd+B");

    section(ui, theme, "Navigation Tips");
    body(
        ui,
        theme,
        "- Click any blue address link in the disassembly to jump to that location",
    );
    body(
        ui,
        theme,
        "- Use Alt+Left/Right to move through your navigation history",
    );
    body(
        ui,
        theme,
        "- The command palette (Cmd+K) accepts hex addresses: type '0x401000' to jump directly",
    );
    body(
        ui,
        theme,
        "- Use the sidebar filter to narrow down functions, strings, or symbols",
    );

    section(ui, theme, "Understanding the Decompiler");
    body(
        ui,
        theme,
        "The decompiler lifts machine code through several stages:",
    );
    body(ui, theme, "  Machine code → Disassembly → IR (register transfer) → C-like AST → Output");
    ui.add_space(4.0);
    body(
        ui,
        theme,
        "- View the IR (key 6) to see how instructions are represented internally",
    );
    body(
        ui,
        theme,
        "- The decompiler applies optimization passes: constant folding, copy propagation, DCE",
    );
    body(
        ui,
        theme,
        "- Control flow is structured using dominance and back-edge analysis",
    );
    body(
        ui,
        theme,
        "- When structuring fails, the decompiler falls back to goto statements",
    );

    section(ui, theme, "Supported Formats");
    body(ui, theme, "Binary formats:  ELF, PE (Windows), Mach-O (macOS)");
    body(ui, theme, "Architectures:   x86_64, ARM64 (AArch64)");
}
