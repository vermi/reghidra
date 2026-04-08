use crate::app::{ReghidraApp, SidePanel};
use crate::context_menu::{
    address_context_menu, apply_context_action, ContextAction, ExtraContext, RenameKind,
};
use egui::Ui;

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let query = app.search_query.to_lowercase();
    let selected_addr = app.selected_address;

    // Pre-collect data we need to avoid borrow conflicts
    let mut navigate_to: Option<u64> = None;
    let mut ctx_action: Option<ContextAction> = None;

    match app.side_panel {
        SidePanel::Functions => {
            let functions = project.functions();
            let filtered: Vec<_> = if query.is_empty() {
                functions.iter().collect()
            } else {
                functions
                    .iter()
                    .filter(|(addr, name)| {
                        name.to_lowercase().contains(&query)
                            || format!("0x{addr:x}").contains(&query)
                    })
                    .collect()
            };

            ui.label(format!("{} functions", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for (addr, name) in &filtered {
                    let label = format!("0x{addr:08x}  {name}");
                    let selected = selected_addr == Some(*addr);
                    let resp = ui.selectable_label(selected, &label);
                    if resp.clicked() {
                        navigate_to = Some(*addr);
                    }
                    let is_bookmarked = project.bookmarks.contains(addr);
                    let has_comment = project.comments.contains_key(addr);
                    address_context_menu(
                        &resp,
                        *addr,
                        RenameKind::Function,
                        is_bookmarked,
                        has_comment,
                        ExtraContext::default(),
                        &mut ctx_action,
                    );
                }
            });
        }

        SidePanel::Symbols => {
            let filtered: Vec<_> = project
                .binary
                .symbols
                .iter()
                .filter(|s| {
                    query.is_empty()
                        || s.name.to_lowercase().contains(&query)
                        || format!("0x{:x}", s.address).contains(&query)
                })
                .collect();

            ui.label(format!("{} symbols", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for sym in &filtered {
                    let kind = match sym.kind {
                        reghidra_core::SymbolKind::Function => "fn",
                        reghidra_core::SymbolKind::Object => "obj",
                        reghidra_core::SymbolKind::Section => "sec",
                        reghidra_core::SymbolKind::File => "file",
                        reghidra_core::SymbolKind::Unknown => "?",
                    };
                    let label = format!("[{kind}] 0x{:08x}  {}", sym.address, sym.name);
                    let selected = selected_addr == Some(sym.address);
                    let resp = ui.selectable_label(selected, &label);
                    if resp.clicked() {
                        navigate_to = Some(sym.address);
                    }
                    let is_func = matches!(sym.kind, reghidra_core::SymbolKind::Function)
                        || project.analysis.function_at(sym.address).is_some();
                    let rename_kind = if is_func {
                        RenameKind::Function
                    } else {
                        RenameKind::None
                    };
                    let is_bookmarked = project.bookmarks.contains(&sym.address);
                    let has_comment = project.comments.contains_key(&sym.address);
                    let string_value = project
                        .binary
                        .strings
                        .iter()
                        .find(|s| s.address == sym.address)
                        .map(|s| s.value.as_str());
                    address_context_menu(
                        &resp,
                        sym.address,
                        rename_kind,
                        is_bookmarked,
                        has_comment,
                        ExtraContext {
                            string_value,
                            variable: None,
                        },
                        &mut ctx_action,
                    );
                }
            });
        }

        SidePanel::Imports => {
            let filtered: Vec<_> = project
                .binary
                .imports
                .iter()
                .filter(|s| query.is_empty() || s.name.to_lowercase().contains(&query))
                .collect();

            ui.label(format!("{} imports", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for imp in &filtered {
                    let label = format!("0x{:08x}  {}", imp.address, imp.name);
                    let selected = selected_addr == Some(imp.address);
                    let resp = ui.selectable_label(selected, &label);
                    if resp.clicked() {
                        navigate_to = Some(imp.address);
                    }
                    let is_func = project.analysis.function_at(imp.address).is_some();
                    let rename_kind = if is_func {
                        RenameKind::Function
                    } else {
                        RenameKind::None
                    };
                    let is_bookmarked = project.bookmarks.contains(&imp.address);
                    let has_comment = project.comments.contains_key(&imp.address);
                    address_context_menu(
                        &resp,
                        imp.address,
                        rename_kind,
                        is_bookmarked,
                        has_comment,
                        ExtraContext::default(),
                        &mut ctx_action,
                    );
                }
            });
        }

        SidePanel::Exports => {
            let filtered: Vec<_> = project
                .binary
                .exports
                .iter()
                .filter(|s| query.is_empty() || s.name.to_lowercase().contains(&query))
                .collect();

            ui.label(format!("{} exports", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for exp in &filtered {
                    let label = format!("0x{:08x}  {}", exp.address, exp.name);
                    let selected = selected_addr == Some(exp.address);
                    let resp = ui.selectable_label(selected, &label);
                    if resp.clicked() {
                        navigate_to = Some(exp.address);
                    }
                    let is_func = project.analysis.function_at(exp.address).is_some();
                    let rename_kind = if is_func {
                        RenameKind::Function
                    } else {
                        RenameKind::None
                    };
                    let is_bookmarked = project.bookmarks.contains(&exp.address);
                    let has_comment = project.comments.contains_key(&exp.address);
                    address_context_menu(
                        &resp,
                        exp.address,
                        rename_kind,
                        is_bookmarked,
                        has_comment,
                        ExtraContext::default(),
                        &mut ctx_action,
                    );
                }
            });
        }

        SidePanel::Sections => {
            let sections: Vec<_> = project.binary.sections.iter().collect();

            ui.label(format!("{} sections", sections.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for sec in &sections {
                    if !query.is_empty() && !sec.name.to_lowercase().contains(&query) {
                        continue;
                    }
                    let perms = format!(
                        "{}{}{}",
                        if sec.is_readable { "r" } else { "-" },
                        if sec.is_writable { "w" } else { "-" },
                        if sec.is_executable { "x" } else { "-" },
                    );
                    let label = format!(
                        "{:<16} 0x{:08x} [{}] size=0x{:x}",
                        sec.name, sec.virtual_address, perms, sec.virtual_size
                    );
                    let selected = selected_addr == Some(sec.virtual_address);
                    let resp = ui.selectable_label(selected, &label);
                    if resp.clicked() {
                        navigate_to = Some(sec.virtual_address);
                    }
                    let addr = sec.virtual_address;
                    let is_bookmarked = project.bookmarks.contains(&addr);
                    let has_comment = project.comments.contains_key(&addr);
                    address_context_menu(
                        &resp,
                        addr,
                        RenameKind::None,
                        is_bookmarked,
                        has_comment,
                        ExtraContext::default(),
                        &mut ctx_action,
                    );
                }
            });
        }

        SidePanel::Strings => {
            let filtered: Vec<_> = project
                .binary
                .strings
                .iter()
                .filter(|s| {
                    query.is_empty()
                        || s.value.to_lowercase().contains(&query)
                        || s.auto_name.to_lowercase().contains(&query)
                })
                .collect();

            ui.label(format!("{} strings", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for s in &filtered {
                    let display_val: String = s.value.chars().take(50).collect();
                    let label = format!(
                        "0x{:08x}  {}  \"{}\"",
                        s.address, s.auto_name, display_val
                    );
                    let selected = selected_addr == Some(s.address);
                    let resp = ui.selectable_label(selected, &label);
                    if resp.clicked() {
                        navigate_to = Some(s.address);
                    }
                    let is_bookmarked = project.bookmarks.contains(&s.address);
                    let has_comment = project.comments.contains_key(&s.address);
                    address_context_menu(
                        &resp,
                        s.address,
                        RenameKind::None,
                        is_bookmarked,
                        has_comment,
                        ExtraContext {
                            string_value: Some(s.value.as_str()),
                            variable: None,
                        },
                        &mut ctx_action,
                    );
                }
            });
        }
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
    if let Some(action) = ctx_action {
        apply_context_action(app, action);
    }
}
