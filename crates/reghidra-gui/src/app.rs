use crate::annotations::AnnotationPopup;
use crate::help::HelpOverlay;
use crate::palette::{CommandPalette, PaletteAction};
use crate::theme::{Theme, ThemeMode};
use crate::undo::{Action, UndoHistory};
use crate::views;
use reghidra_core::Project;
use std::path::PathBuf;

/// Which panel is selected in the sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidePanel {
    Functions,
    Symbols,
    Imports,
    Exports,
    Sections,
    Strings,
}

/// Which main view is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainView {
    Disassembly,
    Decompile,
    Hex,
    Cfg,
    Xrefs,
    Ir,
}

/// Keyboard input mode for vim-like navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal mode: hjkl navigation, shortcuts active.
    Normal,
    /// A text field has focus (search, palette, annotation).
    #[allow(dead_code)]
    Insert,
}

/// Layout mode for the main content area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewLayout {
    Single,
    SplitVertical,
}

pub struct ReghidraApp {
    pub logo: Option<egui::TextureHandle>,
    pub project: Option<Project>,
    pub loading_error: Option<String>,
    pub main_view: MainView,
    pub side_panel: SidePanel,
    pub selected_address: Option<u64>,
    /// Last selected instruction address — code views (decompile, IR, CFG) use
    /// this to keep showing their function when the user navigates to a data address.
    pub code_address: Option<u64>,
    pub search_query: String,
    pub show_bytes_in_disasm: bool,
    pub hex_bytes_per_row: usize,
    pub nav_history: Vec<u64>,
    pub nav_position: usize,

    // Phase 5: Theme
    pub theme: Theme,

    // Phase 5: Undo/redo
    pub undo: UndoHistory,

    // Phase 5: Command palette
    pub palette: CommandPalette,

    // Phase 5: Annotations popup
    pub annotation_popup: AnnotationPopup,

    // Phase 5: Vim-like navigation
    #[allow(dead_code)]
    pub input_mode: InputMode,
    /// Tracks if the user typed 'g' once (for gg = go to top).
    pub g_pending: bool,

    // Phase 5: Split views
    pub layout: ViewLayout,
    pub secondary_view: MainView,
    /// Which pane has keyboard focus in split view (0 = left/primary, 1 = right/secondary).
    pub focused_pane: usize,

    // Phase 5: Context menu state
    #[allow(dead_code)]
    pub context_menu_addr: Option<u64>,

    // Phase 5a: Help overlay
    pub help: HelpOverlay,

    // Mnemonic highlighting (click a mnemonic to highlight all matching)
    pub highlighted_mnemonic: Option<String>,

    /// Monotonically increasing counter bumped on every navigation; views compare
    /// their last-seen value to detect when they need to scroll to selection.
    pub nav_generation: u64,

    // Hover-based cross-view highlighting: double-buffered so all views read
    // last frame's value while writing this frame's value (avoids render-order bugs).
    pub hovered_address: Option<u64>,
    pub hovered_address_next: Option<u64>,

    // Track whether theme has been applied
    theme_applied: bool,

    // Cached decompile output: (function_entry_addr, rename_generation, annotated_lines, displayed_var_names)
    pub decompile_cache:
        Option<(u64, u64, Vec<reghidra_core::AnnotatedLine>, Vec<String>)>,
    /// Bumped whenever a function is renamed so decompile cache knows to refresh.
    pub rename_generation: u64,

    /// Path to the current session file (set after Save/Load Session).
    pub session_path: Option<PathBuf>,
    /// Status message shown briefly in the status bar.
    pub status_message: Option<(String, std::time::Instant)>,
    /// Whether the Loaded Data Sources modal window is currently
    /// shown. Toggled from the View menu and the window's own close
    /// button. Reset to false on project open so a stale "open" flag
    /// from the previous binary doesn't trail forward.
    pub data_sources_open: bool,
}

impl ReghidraApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            logo: None,
            project: None,
            loading_error: None,
            side_panel: SidePanel::Functions,
            main_view: MainView::Disassembly,
            selected_address: None,
            code_address: None,
            search_query: String::new(),
            show_bytes_in_disasm: true,
            hex_bytes_per_row: 16,
            nav_history: Vec::new(),
            nav_position: 0,

            theme: Theme::dark(),
            undo: UndoHistory::new(),
            palette: CommandPalette::new(),
            annotation_popup: AnnotationPopup::new(),
            input_mode: InputMode::Normal,
            g_pending: false,
            layout: ViewLayout::SplitVertical,
            secondary_view: MainView::Decompile,
            focused_pane: 0,
            context_menu_addr: None,
            help: HelpOverlay::new(),
            highlighted_mnemonic: None,
            hovered_address: None,
            hovered_address_next: None,
            nav_generation: 0,
            theme_applied: false,
            decompile_cache: None,
            rename_generation: 0,
            session_path: None,
            status_message: None,
            data_sources_open: false,
        }
    }

    pub fn open_file(&mut self, path: PathBuf) {
        match Project::open(&path) {
            Ok(project) => {
                let entry = project.binary.info.entry_point;
                self.selected_address = Some(entry);
                self.code_address = Some(entry);
                self.nav_history = vec![entry];
                self.nav_position = 0;
                self.project = Some(project);
                self.loading_error = None;
                self.undo = UndoHistory::new();
                self.decompile_cache = None;
                self.hovered_address = None;
                self.hovered_address_next = None;
                self.highlighted_mnemonic = None;
                self.session_path = None;
                self.data_sources_open = false;
                self.nav_generation += 1;
                // Reset per-pane scroll tracking in all views so they scroll
                // to the new binary's entry point on first render.
                Self::reset_scroll_tracking();
            }
            Err(e) => {
                self.loading_error = Some(format!("Failed to load {}: {e}", path.display()));
                self.project = None;
            }
        }
    }

    /// Open a session file, re-loading the binary and restoring annotations.
    pub fn open_session(&mut self, path: PathBuf) {
        match Project::open_with_session(&path) {
            Ok(project) => {
                let entry = project.binary.info.entry_point;
                self.selected_address = Some(entry);
                self.code_address = Some(entry);
                self.nav_history = vec![entry];
                self.nav_position = 0;
                self.project = Some(project);
                self.loading_error = None;
                self.undo = UndoHistory::new();
                self.decompile_cache = None;
                self.hovered_address = None;
                self.hovered_address_next = None;
                self.highlighted_mnemonic = None;
                self.rename_generation += 1;
                self.session_path = Some(path);
                self.data_sources_open = false;
                self.nav_generation += 1;
                Self::reset_scroll_tracking();
                self.set_status("Session loaded");
            }
            Err(e) => {
                self.loading_error = Some(format!("Failed to load session: {e}"));
            }
        }
    }

    /// Save session to the current session path, or prompt for a new path.
    pub fn save_session(&mut self) {
        let path = if let Some(ref p) = self.session_path {
            Some(p.clone())
        } else {
            self.save_session_as()
        };
        if let Some(path) = path {
            self.do_save_session(&path);
        }
    }

    /// Prompt for a new session file path and save.
    pub fn save_session_as(&mut self) -> Option<PathBuf> {
        let default_name = self
            .project
            .as_ref()
            .map(|p| {
                p.binary
                    .info
                    .path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
                    + ".reghidra"
            })
            .unwrap_or_else(|| "session.reghidra".into());

        rfd::FileDialog::new()
            .set_title("Save Session")
            .set_file_name(&default_name)
            .add_filter("Reghidra Session", &["reghidra"])
            .save_file()
    }

    fn do_save_session(&mut self, path: &std::path::Path) {
        if let Some(ref project) = self.project {
            match project.save_session(path) {
                Ok(()) => {
                    self.session_path = Some(path.to_path_buf());
                    self.set_status("Session saved");
                }
                Err(e) => {
                    self.loading_error = Some(format!("Failed to save session: {e}"));
                }
            }
        }
    }

    fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), std::time::Instant::now()));
    }

    /// Clear all per-pane scroll-tracking statics so views re-scroll on next render.
    fn reset_scroll_tracking() {
        use crate::views::{disasm, decompile, hex, ir, cfg};
        disasm::reset_scroll_gen();
        decompile::reset_scroll_gen();
        hex::reset_scroll_gen();
        ir::reset_scroll_gen();
        cfg::reset_scroll_gen();
    }

    /// Returns true if `addr` is a known instruction address.
    fn is_instruction_addr(&self, addr: u64) -> bool {
        self.project.as_ref().is_some_and(|p| {
            p.instructions
                .binary_search_by_key(&addr, |i| i.address)
                .is_ok()
        })
    }


    /// Auto-switch views based on code vs data addresses.
    ///
    /// - Data address: ensure a Hex view is visible. In split mode, switch the
    ///   *opposite* pane to Hex so the user keeps their current view. In single
    ///   mode, switch the active view to Hex.
    /// - Code address from Hex: switch back to Disassembly (same pane logic).
    fn auto_switch_view_for_addr(&mut self, addr: u64) {
        if self.is_instruction_addr(addr) {
            // Code address: only auto-switch back if the current view is Hex
            let view = self.focused_view_mut();
            if *view == MainView::Hex {
                *view = MainView::Disassembly;
            }
        } else {
            // Non-instruction address (data, string, etc.): show Hex.
            // In split mode, switch the opposite pane so the user keeps
            // their current view; in single mode, switch the active view.
            if self.layout == ViewLayout::SplitVertical {
                if self.focused_pane == 0 {
                    self.secondary_view = MainView::Hex;
                } else {
                    self.main_view = MainView::Hex;
                }
            } else {
                *self.focused_view_mut() = MainView::Hex;
            }
        }
    }

    pub fn navigate_to(&mut self, address: u64) {
        let target = if let Some(ref project) = self.project {
            let is_instruction = project
                .instructions
                .binary_search_by_key(&address, |i| i.address)
                .is_ok();

            if is_instruction {
                address
            } else {
                // Check if the address falls inside any loaded section
                let in_section = project.binary.section_at_va(address).is_some();

                if in_section {
                    address
                } else {
                    // Not in any section — snap to nearest instruction
                    project
                        .instructions
                        .iter()
                        .filter(|i| i.address <= address)
                        .last()
                        .or_else(|| project.instructions.first())
                        .map(|i| i.address)
                        .unwrap_or(address)
                }
            }
        } else {
            address
        };

        // Always bump generation so views scroll, even for same address
        self.nav_generation += 1;

        // Truncate forward history
        if self.selected_address != Some(target) {
            if self.nav_position + 1 < self.nav_history.len() {
                self.nav_history.truncate(self.nav_position + 1);
            }
            self.nav_history.push(target);
            self.nav_position = self.nav_history.len() - 1;
        }
        self.selected_address = Some(target);
        if self.is_instruction_addr(target) {
            self.code_address = Some(target);
        }
        self.auto_switch_view_for_addr(target);
    }

    pub fn nav_back(&mut self) {
        if self.nav_position > 0 {
            self.nav_position -= 1;
            let addr = self.nav_history[self.nav_position];
            self.selected_address = Some(addr);
            if self.is_instruction_addr(addr) {
                self.code_address = Some(addr);
            }
            self.nav_generation += 1;
            self.auto_switch_view_for_addr(addr);
        }
    }

    pub fn nav_forward(&mut self) {
        if self.nav_position + 1 < self.nav_history.len() {
            self.nav_position += 1;
            let addr = self.nav_history[self.nav_position];
            self.selected_address = Some(addr);
            if self.is_instruction_addr(addr) {
                self.code_address = Some(addr);
            }
            self.nav_generation += 1;
            self.auto_switch_view_for_addr(addr);
        }
    }

    pub fn toggle_theme(&mut self) {
        self.theme = match self.theme.mode {
            ThemeMode::Dark => Theme::light(),
            ThemeMode::Light => Theme::dark(),
        };
        self.theme_applied = false;
    }

    pub fn toggle_bookmark(&mut self) {
        if let (Some(addr), Some(project)) = (self.selected_address, &mut self.project) {
            if project.bookmarks.contains(&addr) {
                let action = Action::RemoveBookmark { address: addr };
                self.undo.execute(action, project);
            } else {
                let action = Action::AddBookmark { address: addr };
                self.undo.execute(action, project);
            }
        }
    }

    /// Navigate to the next function from the current address.
    pub fn next_function(&mut self) {
        if let Some(project) = &self.project {
            let current = self.selected_address.unwrap_or(0);
            let funcs = project.functions();
            if let Some((addr, _)) = funcs.iter().find(|(a, _)| *a > current) {
                let addr = *addr;
                self.navigate_to(addr);
            }
        }
    }

    /// Navigate to the previous function from the current address.
    pub fn prev_function(&mut self) {
        if let Some(project) = &self.project {
            let current = self.selected_address.unwrap_or(u64::MAX);
            let funcs = project.functions();
            if let Some((addr, _)) = funcs.iter().rev().find(|(a, _)| *a < current) {
                let addr = *addr;
                self.navigate_to(addr);
            }
        }
    }

    /// Navigate to the next instruction relative to the current address.
    pub fn next_instruction(&mut self) {
        if let Some(project) = &self.project {
            let current = self.selected_address.unwrap_or(0);
            if let Some(idx) = project
                .instructions
                .iter()
                .position(|i| i.address == current)
            {
                if idx + 1 < project.instructions.len() {
                    let addr = project.instructions[idx + 1].address;
                    self.navigate_to(addr);
                }
            }
        }
    }

    /// Navigate to the previous instruction relative to the current address.
    pub fn prev_instruction(&mut self) {
        if let Some(project) = &self.project {
            let current = self.selected_address.unwrap_or(0);
            if let Some(idx) = project
                .instructions
                .iter()
                .position(|i| i.address == current)
            {
                if idx > 0 {
                    let addr = project.instructions[idx - 1].address;
                    self.navigate_to(addr);
                }
            }
        }
    }

    /// Navigate to the first instruction.
    pub fn first_instruction(&mut self) {
        if let Some(project) = &self.project {
            if let Some(insn) = project.instructions.first() {
                let addr = insn.address;
                self.navigate_to(addr);
            }
        }
    }

    /// Navigate to the last instruction.
    pub fn last_instruction(&mut self) {
        if let Some(project) = &self.project {
            if let Some(insn) = project.instructions.last() {
                let addr = insn.address;
                self.navigate_to(addr);
            }
        }
    }

    /// Get the active view ref for the focused pane (primary or secondary).
    pub fn focused_view_mut(&mut self) -> &mut MainView {
        if self.layout == ViewLayout::SplitVertical && self.focused_pane == 1 {
            &mut self.secondary_view
        } else {
            &mut self.main_view
        }
    }
}

impl eframe::App for ReghidraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Double-buffer hover: publish last frame's writes so all views read the
        // same value regardless of render order, then clear the write slot.
        self.hovered_address = self.hovered_address_next.take();

        // Throttle repaints: only repaint at ~30 FPS max to avoid pegging CPU
        ctx.request_repaint_after(std::time::Duration::from_millis(33));

        // Apply theme
        if !self.theme_applied {
            self.theme.apply(ctx);
            self.theme_applied = true;
        }

        // Determine input mode: Insert if any text field has focus or modals are open
        let modals_open = self.palette.open
            || self.annotation_popup.open
            || self.help.open
            || self.data_sources_open;

        // Global keyboard shortcuts (always active)
        let mut open_comment = false;
        let mut open_rename = false;

        ctx.input(|i| {
            // Cmd+O: Open file
            if i.key_pressed(egui::Key::O) && i.modifiers.command {
                // handled below — can't borrow self inside closure safely
            }
            // Alt+Left/Right: nav back/forward
            if i.key_pressed(egui::Key::ArrowLeft) && i.modifiers.alt {
                self.nav_back();
            }
            if i.key_pressed(egui::Key::ArrowRight) && i.modifiers.alt {
                self.nav_forward();
            }
            // Cmd+K: Command palette
            if i.key_pressed(egui::Key::K) && i.modifiers.command {
                self.palette.toggle();
            }
            // Cmd+Z / Cmd+Shift+Z: Undo/redo
            if i.key_pressed(egui::Key::Z) && i.modifiers.command && !i.modifiers.shift {
                if let Some(ref mut project) = self.project {
                    if self.undo.is_next_undo_rename() {
                        self.rename_generation += 1;
                        self.decompile_cache = None;
                    }
                    self.undo.undo(project);
                }
            }
            if i.key_pressed(egui::Key::Z) && i.modifiers.command && i.modifiers.shift {
                if let Some(ref mut project) = self.project {
                    if self.undo.is_next_redo_rename() {
                        self.rename_generation += 1;
                        self.decompile_cache = None;
                    }
                    self.undo.redo(project);
                }
            }
            // Cmd+B: Toggle bookmark
            if i.key_pressed(egui::Key::B) && i.modifiers.command {
                // handled after closure
            }
            // Cmd+D: Toggle theme
            if i.key_pressed(egui::Key::D) && i.modifiers.command {
                // handled after closure
            }

            // Reset g_pending on mouse click
            if i.pointer.any_click() {
                self.g_pending = false;
            }
        });

        // Handle F1: Toggle help
        if ctx.input(|i| i.key_pressed(egui::Key::F1)) {
            self.help.toggle();
        }
        // Handle Cmd+O
        if ctx.input(|i| i.key_pressed(egui::Key::O) && i.modifiers.command) {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Open Binary")
                .pick_file()
            {
                self.open_file(path);
            }
        }
        // Handle Cmd+S: Save session
        if ctx.input(|i| i.key_pressed(egui::Key::S) && i.modifiers.command && !i.modifiers.shift) {
            if self.project.is_some() {
                self.save_session();
            }
        }
        // Handle Cmd+Shift+S: Save session as
        if ctx.input(|i| i.key_pressed(egui::Key::S) && i.modifiers.command && i.modifiers.shift) {
            if self.project.is_some() {
                if let Some(path) = self.save_session_as() {
                    self.do_save_session(&path);
                }
            }
        }
        // Handle Cmd+B
        if ctx.input(|i| i.key_pressed(egui::Key::B) && i.modifiers.command) {
            self.toggle_bookmark();
        }
        // Handle Cmd+D
        if ctx.input(|i| i.key_pressed(egui::Key::D) && i.modifiers.command) {
            self.toggle_theme();
        }

        // Vim-like keys: only active when no modals, no text editing active, project loaded.
        // wants_keyboard_input() returns true only when a TextEdit (or similar) widget
        // actually has focus — unlike checking for Text events which fire on every keypress.
        let suppress_vim = modals_open || ctx.wants_keyboard_input();

        if !suppress_vim && self.project.is_some() {
            ctx.input(|i| {
                if !i.modifiers.command && !i.modifiers.alt && !i.modifiers.ctrl {
                    // j/k: next/prev instruction
                    if i.key_pressed(egui::Key::J) {
                        self.next_instruction();
                        self.g_pending = false;
                    }
                    if i.key_pressed(egui::Key::K) {
                        self.prev_instruction();
                        self.g_pending = false;
                    }
                    // n/N: next/prev function
                    if i.key_pressed(egui::Key::N) {
                        if i.modifiers.shift {
                            self.prev_function();
                        } else {
                            self.next_function();
                        }
                        self.g_pending = false;
                    }
                    // gg: go to first instruction, G: go to last
                    if i.key_pressed(egui::Key::G) {
                        if i.modifiers.shift {
                            self.last_instruction();
                            self.g_pending = false;
                        } else if self.g_pending {
                            self.first_instruction();
                            self.g_pending = false;
                        } else {
                            self.g_pending = true;
                        }
                    }
                    // Reset g_pending on any other key
                    if self.g_pending
                        && !i.key_pressed(egui::Key::G)
                        && i.events.iter().any(|e| {
                            matches!(e, egui::Event::Key { pressed: true, .. })
                        })
                    {
                        self.g_pending = false;
                    }

                    // ;: add comment
                    if i.key_pressed(egui::Key::Semicolon) {
                        open_comment = true;
                    }
                    // r: rename function
                    if i.key_pressed(egui::Key::R) {
                        open_rename = true;
                    }
                    // x: switch to xrefs view
                    if i.key_pressed(egui::Key::X) {
                        *self.focused_view_mut() = MainView::Xrefs;
                    }
                    // d: switch to decompile view (without cmd)
                    if i.key_pressed(egui::Key::D) {
                        *self.focused_view_mut() = MainView::Decompile;
                    }
                    // Space: toggle split view
                    if i.key_pressed(egui::Key::Space) {
                        self.layout = match self.layout {
                            ViewLayout::Single => ViewLayout::SplitVertical,
                            ViewLayout::SplitVertical => ViewLayout::Single,
                        };
                    }
                    // Tab: switch focused pane in split view
                    if i.key_pressed(egui::Key::Tab)
                        && self.layout == ViewLayout::SplitVertical
                    {
                        self.focused_pane = 1 - self.focused_pane;
                    }
                    // 1-6: switch views (respects focused pane)
                    if i.key_pressed(egui::Key::Num1) {
                        *self.focused_view_mut() = MainView::Disassembly;
                    }
                    if i.key_pressed(egui::Key::Num2) {
                        *self.focused_view_mut() = MainView::Decompile;
                    }
                    if i.key_pressed(egui::Key::Num3) {
                        *self.focused_view_mut() = MainView::Hex;
                    }
                    if i.key_pressed(egui::Key::Num4) {
                        *self.focused_view_mut() = MainView::Cfg;
                    }
                    if i.key_pressed(egui::Key::Num5) {
                        *self.focused_view_mut() = MainView::Xrefs;
                    }
                    if i.key_pressed(egui::Key::Num6) {
                        *self.focused_view_mut() = MainView::Ir;
                    }
                    // ?: toggle help
                    if i.key_pressed(egui::Key::Questionmark) {
                        self.help.toggle();
                    }
                }
            });
        }

        // Open annotation popups after input processing
        if open_comment {
            if let Some(addr) = self.selected_address {
                let existing = self
                    .project
                    .as_ref()
                    .and_then(|p| p.comments.get(&addr))
                    .cloned();
                self.annotation_popup
                    .open_comment(addr, existing.as_deref());
            }
        }
        if open_rename {
            if let Some(addr) = self.selected_address {
                let existing = self
                    .project
                    .as_ref()
                    .and_then(|p| p.renamed_functions.get(&addr))
                    .cloned();
                self.annotation_popup
                    .open_rename_function(addr, existing.as_deref());
            }
        }

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open... (Cmd+O)").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Open Binary")
                            .pick_file()
                        {
                            self.open_file(path);
                        }
                        ui.close_menu();
                    }
                    if self.project.is_some() {
                        if ui.button("Load Signatures... (.sig)").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_title("Load FLIRT Signatures")
                                .add_filter("IDA Signatures", &["sig"])
                                .pick_file()
                            {
                                if let Some(ref mut project) = self.project {
                                    match project.load_signatures(&path) {
                                        Ok(count) => {
                                            self.loading_error = None;
                                            log::info!("Loaded signatures: {count} functions matched");
                                        }
                                        Err(e) => {
                                            self.loading_error = Some(format!(
                                                "Failed to load signatures: {e}"
                                            ));
                                        }
                                    }
                                }
                            }
                            ui.close_menu();
                        }
                    }
                    ui.separator();
                    if ui.button("Open Session...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Open Session")
                            .add_filter("Reghidra Session", &["reghidra"])
                            .pick_file()
                        {
                            self.open_session(path);
                        }
                        ui.close_menu();
                    }
                    if self.project.is_some() {
                        if ui.button("Save Session (Cmd+S)").clicked() {
                            self.save_session();
                            ui.close_menu();
                        }
                        if ui.button("Save Session As... (Cmd+Shift+S)").clicked() {
                            if let Some(path) = self.save_session_as() {
                                self.do_save_session(&path);
                            }
                            ui.close_menu();
                        }
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("View", |ui| {
                    if ui
                        .radio_value(&mut self.main_view, MainView::Disassembly, "Disassembly (1)")
                        .clicked()
                    {
                        ui.close_menu();
                    }
                    if ui
                        .radio_value(&mut self.main_view, MainView::Decompile, "Decompile (2)")
                        .clicked()
                    {
                        ui.close_menu();
                    }
                    if ui
                        .radio_value(&mut self.main_view, MainView::Hex, "Hex (3)")
                        .clicked()
                    {
                        ui.close_menu();
                    }
                    if ui
                        .radio_value(
                            &mut self.main_view,
                            MainView::Cfg,
                            "Control Flow Graph (4)",
                        )
                        .clicked()
                    {
                        ui.close_menu();
                    }
                    if ui
                        .radio_value(
                            &mut self.main_view,
                            MainView::Xrefs,
                            "Cross-References (5)",
                        )
                        .clicked()
                    {
                        ui.close_menu();
                    }
                    if ui
                        .radio_value(&mut self.main_view, MainView::Ir, "IR (6)")
                        .clicked()
                    {
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.checkbox(&mut self.show_bytes_in_disasm, "Show bytes in disassembly");
                    ui.separator();
                    let layout_label = match self.layout {
                        ViewLayout::Single => "Split View (Space)",
                        ViewLayout::SplitVertical => "Single View (Space)",
                    };
                    if ui.button(layout_label).clicked() {
                        self.layout = match self.layout {
                            ViewLayout::Single => ViewLayout::SplitVertical,
                            ViewLayout::SplitVertical => ViewLayout::Single,
                        };
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Loaded Data Sources...").clicked() {
                        self.data_sources_open = !self.data_sources_open;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Navigate", |ui| {
                    if ui.button("Back (Alt+Left)").clicked() {
                        self.nav_back();
                        ui.close_menu();
                    }
                    if ui.button("Forward (Alt+Right)").clicked() {
                        self.nav_forward();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Command Palette (Cmd+K)").clicked() {
                        self.palette.toggle();
                        ui.close_menu();
                    }
                    if ui.button("Next Function (n)").clicked() {
                        self.next_function();
                        ui.close_menu();
                    }
                    if ui.button("Prev Function (N)").clicked() {
                        self.prev_function();
                        ui.close_menu();
                    }
                });

                ui.menu_button("Edit", |ui| {
                    let can_undo = self.undo.can_undo();
                    let can_redo = self.undo.can_redo();
                    let undo_label = if let Some(desc) = self.undo.undo_description() {
                        format!("Undo: {desc} (Cmd+Z)")
                    } else {
                        "Undo (Cmd+Z)".into()
                    };
                    let redo_label = if let Some(desc) = self.undo.redo_description() {
                        format!("Redo: {desc} (Cmd+Shift+Z)")
                    } else {
                        "Redo (Cmd+Shift+Z)".into()
                    };

                    if ui
                        .add_enabled(can_undo, egui::Button::new(undo_label))
                        .clicked()
                    {
                        if let Some(ref mut project) = self.project {
                            self.undo.undo(project);
                        }
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(can_redo, egui::Button::new(redo_label))
                        .clicked()
                    {
                        if let Some(ref mut project) = self.project {
                            self.undo.redo(project);
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Add Comment (;)").clicked() {
                        if let Some(addr) = self.selected_address {
                            let existing = self
                                .project
                                .as_ref()
                                .and_then(|p| p.comments.get(&addr))
                                .cloned();
                            self.annotation_popup
                                .open_comment(addr, existing.as_deref());
                        }
                        ui.close_menu();
                    }
                    if ui.button("Rename Function (r)").clicked() {
                        if let Some(addr) = self.selected_address {
                            let existing = self
                                .project
                                .as_ref()
                                .and_then(|p| p.renamed_functions.get(&addr))
                                .cloned();
                            self.annotation_popup
                                .open_rename_function(addr, existing.as_deref());
                        }
                        ui.close_menu();
                    }
                    if ui.button("Toggle Bookmark (Cmd+B)").clicked() {
                        self.toggle_bookmark();
                        ui.close_menu();
                    }
                });

                ui.menu_button("Theme", |ui| {
                    if ui
                        .radio_value(&mut self.theme.mode, ThemeMode::Dark, "Dark (Cmd+D)")
                        .clicked()
                    {
                        self.theme = Theme::dark();
                        self.theme_applied = false;
                        ui.close_menu();
                    }
                    if ui
                        .radio_value(&mut self.theme.mode, ThemeMode::Light, "Light (Cmd+D)")
                        .clicked()
                    {
                        self.theme = Theme::light();
                        self.theme_applied = false;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("Quick Start Guide (F1)").clicked() {
                        self.help.toggle();
                        ui.close_menu();
                    }
                    if ui.button("Keyboard Shortcuts").clicked() {
                        self.help.open = true;
                        ui.close_menu();
                    }
                });
            });
        });

        // Status bar
        let mut open_data_sources = false;
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(ref project) = self.project {
                    let info = &project.binary.info;
                    ui.label(format!(
                        "{} | {} | {}",
                        info.path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy(),
                        info.format,
                        info.architecture,
                    ));
                    ui.separator();
                    ui.label(format!(
                        "{} insns | {} fns | {} xrefs | {} strings",
                        project.instructions.len(),
                        project.analysis.functions.len(),
                        project.analysis.xrefs.total_count(),
                        project.binary.strings.len(),
                    ));

                    // Show signature status. Clickable so the user can
                    // jump straight from "N signatures matched" into
                    // the Loaded Data Sources panel and see *which*
                    // dbs/archives are responsible.
                    if let Some(ref status) = project.sig_status {
                        ui.separator();
                        let resp = ui
                            .add(
                                egui::Label::new(
                                    egui::RichText::new(status)
                                        .color(self.theme.func_header_sig),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_text("Open Loaded Data Sources");
                        if resp.hovered() {
                            ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        if resp.clicked() {
                            open_data_sources = true;
                        }
                    }

                    // Show bookmark indicator
                    if let Some(addr) = self.selected_address {
                        if project.bookmarks.contains(&addr) {
                            ui.separator();
                            ui.colored_label(self.theme.bookmark, "BOOKMARKED");
                        }
                    }

                    // Show transient status message (visible for 3 seconds)
                    if let Some((ref msg, ref instant)) = self.status_message {
                        if instant.elapsed() < std::time::Duration::from_secs(3) {
                            ui.separator();
                            ui.colored_label(self.theme.func_header_sig, msg);
                        }
                    }

                    // Show vim key hints
                    ui.separator();
                    ui.colored_label(
                        self.theme.text_dim,
                        "j/k:nav  n/N:fn  ;:comment  r:rename  1-6:views  Space:split  ?:help",
                    );

                    if let Some(addr) = self.selected_address {
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                ui.label(format!("0x{addr:08x}"));
                            },
                        );
                    }
                } else {
                    ui.label("No binary loaded -- File > Open or Cmd+O");
                }
            });
        });
        if open_data_sources {
            self.data_sources_open = true;
        }

        if self.project.is_none() {
            // Load logo texture on first frame
            let logo = self.logo.get_or_insert_with(|| {
                let png_bytes = include_bytes!("../../../assets/reghidra.png");
                let img = image::load_from_memory(png_bytes)
                    .expect("Failed to decode logo PNG")
                    .into_rgba8();
                let size = [img.width() as usize, img.height() as usize];
                let pixels = img.into_raw();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                ctx.load_texture("logo", color_image, egui::TextureOptions::LINEAR)
            });
            let logo_texture = logo.id();

            // Welcome screen
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    let logo_size = egui::vec2(128.0, 128.0);
                    ui.image(egui::load::SizedTexture::new(logo_texture, logo_size));
                    ui.add_space(16.0);
                    ui.heading("Reghidra");
                    ui.label("A modern reverse engineering framework");
                    ui.add_space(20.0);
                    if ui.button("Open Binary...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Open Binary")
                            .pick_file()
                        {
                            self.open_file(path);
                        }
                    }
                    if ui.button("Open Session...").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Open Session")
                            .add_filter("Reghidra Session", &["reghidra"])
                            .pick_file()
                        {
                            self.open_session(path);
                        }
                    }
                    ui.add_space(8.0);
                    if ui.button("Quick Start Guide (F1)").clicked() {
                        self.help.toggle();
                    }
                    if let Some(ref err) = self.loading_error {
                        ui.add_space(10.0);
                        ui.colored_label(egui::Color32::RED, err);
                    }
                });
            });

            // Help overlay (available even without a binary loaded)
            let theme_for_welcome = self.theme.clone();
            self.help.show(ctx, &theme_for_welcome);
            return;
        }

        // Left sidebar: panel selector + content
        egui::SidePanel::left("side_panel")
            .default_width(280.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                // Panel selector tabs
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.side_panel, SidePanel::Functions, "Fn");
                    ui.selectable_value(&mut self.side_panel, SidePanel::Symbols, "Sym");
                    ui.selectable_value(&mut self.side_panel, SidePanel::Imports, "Imp");
                    ui.selectable_value(&mut self.side_panel, SidePanel::Exports, "Exp");
                    ui.selectable_value(&mut self.side_panel, SidePanel::Sections, "Sec");
                    ui.selectable_value(&mut self.side_panel, SidePanel::Strings, "Str");
                });
                ui.separator();

                // Search box
                ui.horizontal(|ui| {
                    ui.label("Filter:");
                    ui.text_edit_singleline(&mut self.search_query);
                });
                ui.separator();

                views::side_panel::render(self, ui);
            });

        // Main content area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.layout {
                ViewLayout::Single => {
                    render_view_tabs_and_content(self, ui, true);
                }
                ViewLayout::SplitVertical => {
                    // Give each pane its own clipping rect and id_salt so
                    // scroll areas and widgets are fully independent.
                    let available = ui.available_rect_before_wrap();
                    let half_width = available.width() / 2.0 - 2.0;
                    let sep_x = available.min.x + half_width + 1.0;

                    let left_rect = egui::Rect::from_min_size(
                        available.min,
                        egui::vec2(half_width, available.height()),
                    );
                    let right_rect = egui::Rect::from_min_size(
                        egui::pos2(sep_x + 3.0, available.min.y),
                        egui::vec2(half_width, available.height()),
                    );

                    // Only switch focused pane on mouse click (not hover)
                    if ctx.input(|i| i.pointer.any_click()) {
                        if let Some(pos) = ctx.input(|i| i.pointer.interact_pos()) {
                            if left_rect.contains(pos) {
                                self.focused_pane = 0;
                            } else if right_rect.contains(pos) {
                                self.focused_pane = 1;
                            }
                        }
                    }

                    // Left pane (primary) — unique id_salt + clip rect
                    ui.allocate_new_ui(
                        egui::UiBuilder::new()
                            .max_rect(left_rect)
                            .id_salt("split_left"),
                        |ui| {
                            ui.set_clip_rect(left_rect);
                            render_view_tabs_and_content(self, ui, true);
                        },
                    );

                    // Separator line
                    ui.painter().line_segment(
                        [
                            egui::pos2(sep_x, available.min.y),
                            egui::pos2(sep_x, available.max.y),
                        ],
                        ui.visuals().widgets.noninteractive.bg_stroke,
                    );

                    // Right pane (secondary) — unique id_salt + clip rect
                    ui.allocate_new_ui(
                        egui::UiBuilder::new()
                            .max_rect(right_rect)
                            .id_salt("split_right"),
                        |ui| {
                            ui.set_clip_rect(right_rect);
                            render_view_tabs_and_content(self, ui, false);
                        },
                    );
                }
            }
        });

        // Overlays: Command palette and annotation popup
        // These need mutable access to project, so we handle them carefully

        // Command palette
        if self.palette.open {
            if let Some(ref project) = self.project {
                self.palette.update_entries(project);
            }
        }
        let theme_clone = self.theme.clone();
        if let Some(action) = self.palette.show(ctx, &theme_clone) {
            match action {
                PaletteAction::NavigateTo(addr) => self.navigate_to(addr),
                PaletteAction::SwitchView(view) => *self.focused_view_mut() = view,
                PaletteAction::ToggleTheme => self.toggle_theme(),
                PaletteAction::ShowHelp => self.help.toggle(),
                PaletteAction::SaveSession => {
                    if self.project.is_some() {
                        self.save_session();
                    }
                }
                PaletteAction::OpenSession => {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Open Session")
                        .add_filter("Reghidra Session", &["reghidra"])
                        .pick_file()
                    {
                        self.open_session(path);
                    }
                }
                PaletteAction::GoToAddress => {}
            }
        }

        // Annotation popup
        if self.annotation_popup.open {
            // Any rename (function/label/variable) invalidates the decompile cache.
            let was_rename = !matches!(
                self.annotation_popup.kind,
                crate::annotations::AnnotationKind::Comment
            );
            if let Some(ref mut project) = self.project {
                let committed = self.annotation_popup
                    .show(ctx, &theme_clone, project, &mut self.undo);
                if committed && was_rename {
                    self.rename_generation += 1;
                    self.decompile_cache = None;
                }
            }
        }

        // Help overlay
        self.help.show(ctx, &theme_clone);

        // Loaded Data Sources modal
        views::data_sources::render_window(self, ctx);
    }
}

/// Render view tabs and the selected view's content.
fn render_view_tabs_and_content(app: &mut ReghidraApp, ui: &mut egui::Ui, is_primary: bool) {
    let view = if is_primary {
        &mut app.main_view
    } else {
        &mut app.secondary_view
    };

    ui.horizontal(|ui| {
        ui.selectable_value(view, MainView::Disassembly, "Disassembly");
        ui.selectable_value(view, MainView::Decompile, "Decompile");
        ui.selectable_value(view, MainView::Hex, "Hex");
        ui.selectable_value(view, MainView::Cfg, "CFG");
        ui.selectable_value(view, MainView::Xrefs, "Xrefs");
        ui.selectable_value(view, MainView::Ir, "IR");
    });
    ui.separator();

    let active_view = *view;
    match active_view {
        MainView::Disassembly => views::disasm::render(app, ui),
        MainView::Decompile => views::decompile::render(app, ui),
        MainView::Hex => views::hex::render(app, ui),
        MainView::Cfg => views::cfg::render(app, ui),
        MainView::Xrefs => views::xrefs::render(app, ui),
        MainView::Ir => views::ir::render(app, ui),
    }
}
