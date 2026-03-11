use egui::Color32;

/// Which theme variant is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    Dark,
    Light,
}

/// All colors used across views, centralized for theming.
#[derive(Debug, Clone)]
pub struct Theme {
    pub mode: ThemeMode,

    // General
    #[allow(dead_code)]
    pub bg_primary: Color32,
    #[allow(dead_code)]
    pub bg_secondary: Color32,
    pub bg_selected: Color32,
    pub bg_mnemonic_highlight: Color32,
    pub text_primary: Color32,
    pub text_secondary: Color32,
    pub text_dim: Color32,
    #[allow(dead_code)]
    pub separator: Color32,

    // Addresses
    pub addr_normal: Color32,
    pub addr_selected: Color32,

    // Disassembly mnemonics
    pub mnemonic_control: Color32,
    pub mnemonic_data: Color32,
    pub mnemonic_arith: Color32,
    pub mnemonic_cmp: Color32,
    pub mnemonic_nop: Color32,
    pub mnemonic_default: Color32,

    // Annotations
    pub comment: Color32,
    pub func_header: Color32,
    pub func_header_auto: Color32,
    pub xref_hint: Color32,
    pub xref_func: Color32,
    pub xref_string: Color32,
    pub bookmark: Color32,

    // Bytes
    pub hex_bytes: Color32,
    pub hex_ascii: Color32,
    pub column_header: Color32,

    // Decompile
    pub decomp_comment: Color32,
    pub decomp_control: Color32,
    pub decomp_return: Color32,
    pub decomp_goto: Color32,
    pub decomp_type: Color32,
    pub decomp_structural: Color32,
    pub decomp_default: Color32,

    // CFG
    pub cfg_entry: Color32,
    pub cfg_active: Color32,
    pub cfg_block: Color32,
    pub cfg_edge_true: Color32,
    pub cfg_edge_false: Color32,
    pub cfg_edge_uncond: Color32,
    pub cfg_border: Color32,
    pub cfg_border_active: Color32,

    // IR
    pub ir_block: Color32,
    pub ir_data: Color32,
    pub ir_arith: Color32,
    pub ir_cmp: Color32,
    pub ir_control: Color32,
    pub ir_ext: Color32,
    pub ir_nop: Color32,
    pub ir_unimpl: Color32,
    pub ir_phi: Color32,

    // Xrefs
    pub xref_call: Color32,
    pub xref_jump: Color32,
    pub xref_cond_jump: Color32,
    pub xref_data_read: Color32,
    pub xref_data_write: Color32,
    pub xref_addr_of: Color32,
    pub xref_string_ref: Color32,
    pub xref_to_header: Color32,
    pub xref_from_header: Color32,

    // Command palette
    pub palette_bg: Color32,
    pub palette_border: Color32,
    #[allow(dead_code)]
    pub palette_match: Color32,
    pub palette_selected_bg: Color32,
}

impl Theme {
    pub fn dark() -> Self {
        Self {
            mode: ThemeMode::Dark,

            bg_primary: Color32::from_rgb(30, 30, 35),
            bg_secondary: Color32::from_rgb(40, 40, 48),
            bg_selected: Color32::from_rgb(50, 55, 75),
            bg_mnemonic_highlight: Color32::from_rgb(60, 50, 30),
            text_primary: Color32::from_rgb(220, 220, 220),
            text_secondary: Color32::from_rgb(150, 150, 150),
            text_dim: Color32::from_rgb(100, 100, 100),
            separator: Color32::from_rgb(60, 60, 70),

            addr_normal: Color32::from_rgb(100, 149, 237),
            addr_selected: Color32::from_rgb(255, 255, 100),

            mnemonic_control: Color32::from_rgb(255, 120, 120),
            mnemonic_data: Color32::from_rgb(130, 200, 255),
            mnemonic_arith: Color32::from_rgb(200, 200, 130),
            mnemonic_cmp: Color32::from_rgb(255, 180, 100),
            mnemonic_nop: Color32::from_rgb(100, 100, 100),
            mnemonic_default: Color32::from_rgb(200, 200, 200),

            comment: Color32::from_rgb(80, 200, 80),
            func_header: Color32::from_rgb(255, 200, 60),
            func_header_auto: Color32::from_rgb(200, 170, 80),
            xref_hint: Color32::from_rgb(120, 120, 180),
            xref_func: Color32::from_rgb(180, 180, 255),
            xref_string: Color32::from_rgb(180, 255, 180),
            bookmark: Color32::from_rgb(255, 200, 60),

            hex_bytes: Color32::from_rgb(200, 200, 200),
            hex_ascii: Color32::from_rgb(180, 220, 180),
            column_header: Color32::from_rgb(150, 150, 150),

            decomp_comment: Color32::from_rgb(100, 160, 100),
            decomp_control: Color32::from_rgb(200, 150, 255),
            decomp_return: Color32::from_rgb(255, 120, 120),
            decomp_goto: Color32::from_rgb(255, 180, 100),
            decomp_type: Color32::from_rgb(100, 200, 255),
            decomp_structural: Color32::from_rgb(150, 150, 150),
            decomp_default: Color32::from_rgb(220, 220, 220),

            cfg_entry: Color32::from_rgb(100, 255, 100),
            cfg_active: Color32::from_rgb(255, 200, 60),
            cfg_block: Color32::from_rgb(150, 150, 255),
            cfg_edge_true: Color32::from_rgb(100, 255, 100),
            cfg_edge_false: Color32::from_rgb(255, 100, 100),
            cfg_edge_uncond: Color32::from_rgb(150, 150, 150),
            cfg_border: Color32::from_rgb(60, 60, 80),
            cfg_border_active: Color32::from_rgb(255, 200, 60),

            ir_block: Color32::from_rgb(150, 150, 255),
            ir_data: Color32::from_rgb(130, 200, 255),
            ir_arith: Color32::from_rgb(200, 200, 130),
            ir_cmp: Color32::from_rgb(255, 180, 100),
            ir_control: Color32::from_rgb(255, 120, 120),
            ir_ext: Color32::from_rgb(180, 255, 180),
            ir_nop: Color32::from_rgb(100, 100, 100),
            ir_unimpl: Color32::from_rgb(255, 100, 255),
            ir_phi: Color32::from_rgb(200, 200, 255),

            xref_call: Color32::from_rgb(255, 120, 120),
            xref_jump: Color32::from_rgb(255, 180, 100),
            xref_cond_jump: Color32::from_rgb(255, 220, 100),
            xref_data_read: Color32::from_rgb(130, 200, 255),
            xref_data_write: Color32::from_rgb(200, 130, 255),
            xref_addr_of: Color32::from_rgb(150, 255, 150),
            xref_string_ref: Color32::from_rgb(255, 255, 150),
            xref_to_header: Color32::from_rgb(150, 200, 255),
            xref_from_header: Color32::from_rgb(255, 200, 150),

            palette_bg: Color32::from_rgb(40, 40, 50),
            palette_border: Color32::from_rgb(100, 100, 140),
            palette_match: Color32::from_rgb(255, 200, 60),
            palette_selected_bg: Color32::from_rgb(60, 60, 90),
        }
    }

    pub fn light() -> Self {
        Self {
            mode: ThemeMode::Light,

            bg_primary: Color32::from_rgb(250, 250, 250),
            bg_secondary: Color32::from_rgb(240, 240, 245),
            bg_selected: Color32::from_rgb(210, 220, 240),
            bg_mnemonic_highlight: Color32::from_rgb(255, 245, 200),
            text_primary: Color32::from_rgb(30, 30, 30),
            text_secondary: Color32::from_rgb(100, 100, 100),
            text_dim: Color32::from_rgb(160, 160, 160),
            separator: Color32::from_rgb(200, 200, 210),

            addr_normal: Color32::from_rgb(30, 80, 180),
            addr_selected: Color32::from_rgb(180, 130, 0),

            mnemonic_control: Color32::from_rgb(200, 50, 50),
            mnemonic_data: Color32::from_rgb(30, 120, 200),
            mnemonic_arith: Color32::from_rgb(140, 130, 30),
            mnemonic_cmp: Color32::from_rgb(200, 120, 30),
            mnemonic_nop: Color32::from_rgb(180, 180, 180),
            mnemonic_default: Color32::from_rgb(60, 60, 60),

            comment: Color32::from_rgb(30, 140, 30),
            func_header: Color32::from_rgb(160, 120, 0),
            func_header_auto: Color32::from_rgb(140, 120, 50),
            xref_hint: Color32::from_rgb(80, 80, 140),
            xref_func: Color32::from_rgb(80, 80, 200),
            xref_string: Color32::from_rgb(30, 140, 30),
            bookmark: Color32::from_rgb(200, 150, 0),

            hex_bytes: Color32::from_rgb(50, 50, 50),
            hex_ascii: Color32::from_rgb(30, 120, 30),
            column_header: Color32::from_rgb(100, 100, 100),

            decomp_comment: Color32::from_rgb(30, 130, 30),
            decomp_control: Color32::from_rgb(140, 60, 200),
            decomp_return: Color32::from_rgb(200, 50, 50),
            decomp_goto: Color32::from_rgb(200, 120, 30),
            decomp_type: Color32::from_rgb(30, 120, 200),
            decomp_structural: Color32::from_rgb(120, 120, 120),
            decomp_default: Color32::from_rgb(30, 30, 30),

            cfg_entry: Color32::from_rgb(30, 160, 30),
            cfg_active: Color32::from_rgb(180, 130, 0),
            cfg_block: Color32::from_rgb(60, 60, 200),
            cfg_edge_true: Color32::from_rgb(30, 160, 30),
            cfg_edge_false: Color32::from_rgb(200, 50, 50),
            cfg_edge_uncond: Color32::from_rgb(120, 120, 120),
            cfg_border: Color32::from_rgb(180, 180, 200),
            cfg_border_active: Color32::from_rgb(180, 130, 0),

            ir_block: Color32::from_rgb(60, 60, 200),
            ir_data: Color32::from_rgb(30, 120, 200),
            ir_arith: Color32::from_rgb(140, 130, 30),
            ir_cmp: Color32::from_rgb(200, 120, 30),
            ir_control: Color32::from_rgb(200, 50, 50),
            ir_ext: Color32::from_rgb(30, 140, 30),
            ir_nop: Color32::from_rgb(180, 180, 180),
            ir_unimpl: Color32::from_rgb(200, 50, 200),
            ir_phi: Color32::from_rgb(100, 100, 200),

            xref_call: Color32::from_rgb(200, 50, 50),
            xref_jump: Color32::from_rgb(200, 120, 30),
            xref_cond_jump: Color32::from_rgb(180, 150, 0),
            xref_data_read: Color32::from_rgb(30, 120, 200),
            xref_data_write: Color32::from_rgb(140, 60, 200),
            xref_addr_of: Color32::from_rgb(30, 160, 30),
            xref_string_ref: Color32::from_rgb(180, 150, 0),
            xref_to_header: Color32::from_rgb(30, 100, 200),
            xref_from_header: Color32::from_rgb(200, 120, 30),

            palette_bg: Color32::from_rgb(255, 255, 255),
            palette_border: Color32::from_rgb(150, 150, 180),
            palette_match: Color32::from_rgb(200, 140, 0),
            palette_selected_bg: Color32::from_rgb(230, 230, 245),
        }
    }

    /// Apply this theme's visuals to the egui context.
    pub fn apply(&self, ctx: &egui::Context) {
        let mut visuals = match self.mode {
            ThemeMode::Dark => egui::Visuals::dark(),
            ThemeMode::Light => egui::Visuals::light(),
        };
        visuals.override_text_color = Some(self.text_primary);
        ctx.set_visuals(visuals);
    }

    pub fn mnemonic_color(&self, mnemonic: &str) -> Color32 {
        let m = mnemonic.to_lowercase();
        if m.starts_with('j')
            || m == "call"
            || m == "ret"
            || m == "bl"
            || m == "blr"
            || m == "b"
            || m.starts_with("b.")
        {
            self.mnemonic_control
        } else if m.starts_with("mov")
            || m == "lea"
            || m == "ldr"
            || m == "str"
            || m == "push"
            || m == "pop"
            || m == "ldp"
            || m == "stp"
        {
            self.mnemonic_data
        } else if m.starts_with("add")
            || m.starts_with("sub")
            || m.starts_with("mul")
            || m.starts_with("div")
            || m.starts_with("and")
            || m.starts_with("or")
            || m.starts_with("xor")
            || m.starts_with("shl")
            || m.starts_with("shr")
            || m == "inc"
            || m == "dec"
            || m == "neg"
            || m == "not"
            || m == "imul"
            || m == "idiv"
        {
            self.mnemonic_arith
        } else if m == "nop" || m == "int3" {
            self.mnemonic_nop
        } else if m.starts_with("cmp") || m.starts_with("test") || m == "tst" {
            self.mnemonic_cmp
        } else {
            self.mnemonic_default
        }
    }

    pub fn colorize_decompile_line(&self, line: &str) -> Color32 {
        let trimmed = line.trim();
        if trimmed.starts_with("/*") || trimmed.starts_with("//") {
            self.decomp_comment
        } else if trimmed.starts_with("if ")
            || trimmed.starts_with("} else")
            || trimmed.starts_with("while ")
            || trimmed.starts_with("for ")
        {
            self.decomp_control
        } else if trimmed.starts_with("return") {
            self.decomp_return
        } else if trimmed.starts_with("goto ") {
            self.decomp_goto
        } else if trimmed.starts_with("void ")
            || trimmed.starts_with("int")
            || trimmed.starts_with("uint")
        {
            self.decomp_type
        } else if trimmed == "{"
            || trimmed == "}"
            || trimmed == "break;"
            || trimmed == "continue;"
        {
            self.decomp_structural
        } else {
            self.decomp_default
        }
    }

    pub fn xref_kind_color(&self, kind: reghidra_core::XRefKind) -> Color32 {
        match kind {
            reghidra_core::XRefKind::Call => self.xref_call,
            reghidra_core::XRefKind::Jump => self.xref_jump,
            reghidra_core::XRefKind::ConditionalJump => self.xref_cond_jump,
            reghidra_core::XRefKind::DataRead => self.xref_data_read,
            reghidra_core::XRefKind::DataWrite => self.xref_data_write,
            reghidra_core::XRefKind::AddressOf => self.xref_addr_of,
            reghidra_core::XRefKind::StringRef => self.xref_string_ref,
        }
    }
}
