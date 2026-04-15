//! One synthetic-Features unit test per bundled rule.
//! For each rule we (a) build a Features that MUST fire it and (b) one that MUST NOT.

use reghidra_detect::*;
use std::collections::HashMap;

fn empty_feats() -> Features { Features::default() }

fn one_fn(mnemonics: Vec<&str>, apis: Vec<&str>, strings: Vec<&str>) -> Features {
    let mut bf = HashMap::new();
    bf.insert(0x1000, FunctionFeatures {
        name: "t".into(),
        apis: apis.into_iter().map(String::from).collect(),
        string_refs: strings.into_iter().map(String::from).collect(),
        mnemonics: mnemonics.into_iter().map(String::from).collect(),
        xref_in_count: 0, xref_out_count: 0,
    });
    Features { by_function: bf, ..Features::default() }
}

fn load(stem_subdir: &str, stem: &str) -> Vec<Rule> {
    let path = format!("{stem_subdir}/{stem}.yml");
    let src = bundled_rule_contents(&path).expect("bundled rule exists");
    parse_rules_from_str(src, &path).expect("parses")
}

// ─── existing ───────────────────────────────────────────────────────────────

#[test]
fn rdtsc_timing_fires_on_two_rdtscs() {
    let rules = load("anti_analysis", "rdtsc-timing");
    let feats = one_fn(vec!["push", "rdtsc", "mov", "rdtsc"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn rdtsc_timing_no_fire_on_single_rdtsc() {
    let rules = load("anti_analysis", "rdtsc-timing");
    let feats = one_fn(vec!["rdtsc"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

// ─── 16A: anti_analysis ─────────────────────────────────────────────────────

#[test]
fn anti_analysis_isdebuggerpresent_fires() {
    let rules = load("anti_analysis", "isdebuggerpresent");
    let feats = one_fn(vec![], vec!["IsDebuggerPresent"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_isdebuggerpresent_no_fire() {
    let rules = load("anti_analysis", "isdebuggerpresent");
    let feats = one_fn(vec![], vec!["GetLastError"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_checkremotedebuggerpresent_fires() {
    let rules = load("anti_analysis", "checkremotedebuggerpresent");
    let feats = one_fn(vec![], vec!["CheckRemoteDebuggerPresent"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_checkremotedebuggerpresent_no_fire() {
    let rules = load("anti_analysis", "checkremotedebuggerpresent");
    let feats = empty_feats();
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_ntqueryinformationprocess_debug_fires() {
    let rules = load("anti_analysis", "ntqueryinformationprocess-debug");
    let feats = one_fn(vec![], vec!["NtQueryInformationProcess"], vec!["ProcessDebugPort"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_ntqueryinformationprocess_debug_no_fire() {
    // API present but no matching debug-class string
    let rules = load("anti_analysis", "ntqueryinformationprocess-debug");
    let feats = one_fn(vec![], vec!["NtQueryInformationProcess"], vec!["ProcessBasicInformation"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_peb_beingdebugged_fires() {
    let rules = load("anti_analysis", "peb-beingdebugged");
    let feats = one_fn(vec![], vec![], vec!["BeingDebugged"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_peb_beingdebugged_no_fire() {
    let rules = load("anti_analysis", "peb-beingdebugged");
    let feats = empty_feats();
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_peb_ntglobalflag_fires() {
    let rules = load("anti_analysis", "peb-ntglobalflag");
    let feats = one_fn(vec![], vec![], vec!["NtGlobalFlag"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_peb_ntglobalflag_no_fire() {
    let rules = load("anti_analysis", "peb-ntglobalflag");
    let feats = one_fn(vec![], vec![], vec!["NtQuerySystemInformation"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_int3_scan_fires() {
    let rules = load("anti_analysis", "int3-scan");
    let feats = one_fn(vec!["push", "int3", "cmp", "je"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_int3_scan_no_fire() {
    // int3 alone (e.g. a debug breakpoint stub) should not fire
    let rules = load("anti_analysis", "int3-scan");
    let feats = one_fn(vec!["int3"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_vmware_io_port_fires() {
    let rules = load("anti_analysis", "vmware-io-port");
    let feats = one_fn(vec!["mov", "in", "cmp"], vec![], vec!["VMXh"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_vmware_io_port_no_fire() {
    // IN without the VMXh magic should not fire
    let rules = load("anti_analysis", "vmware-io-port");
    let feats = one_fn(vec!["in"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_hypervisor_bit_fires() {
    let rules = load("anti_analysis", "hypervisor-bit");
    let feats = one_fn(vec!["mov", "cpuid", "bt", "jz"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_hypervisor_bit_no_fire() {
    // cpuid without bt should not fire
    let rules = load("anti_analysis", "hypervisor-bit");
    let feats = one_fn(vec!["cpuid", "mov", "cmp"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_cpuid_brand_string_fires() {
    let rules = load("anti_analysis", "cpuid-brand-string");
    let feats = one_fn(vec!["cpuid"], vec![], vec!["VMware"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_cpuid_brand_string_no_fire() {
    // brand string without cpuid should not fire
    let rules = load("anti_analysis", "cpuid-brand-string");
    let feats = one_fn(vec!["mov"], vec![], vec!["VMware"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_sleep_skew_fires() {
    let rules = load("anti_analysis", "sleep-skew");
    let feats = one_fn(vec!["rdtsc", "sub", "rdtsc"], vec!["Sleep"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_sleep_skew_no_fire() {
    // rdtsc without Sleep should not fire this specific rule
    let rules = load("anti_analysis", "sleep-skew");
    let feats = one_fn(vec!["rdtsc", "rdtsc"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_sandbox_username_check_fires() {
    let rules = load("anti_analysis", "sandbox-username-check");
    let feats = one_fn(vec![], vec!["GetUserNameA"], vec!["sandbox"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_sandbox_username_check_no_fire() {
    // GetUserName without a suspicious username string
    let rules = load("anti_analysis", "sandbox-username-check");
    let feats = one_fn(vec![], vec!["GetUserNameA"], vec!["DESKTOP-XYZ123"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn anti_analysis_process_list_scan_fires() {
    let rules = load("anti_analysis", "process-list-scan");
    let feats = one_fn(vec![], vec!["CreateToolhelp32Snapshot", "Process32First", "Process32Next"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn anti_analysis_process_list_scan_no_fire() {
    // snapshot alone without Process32First/Next should not fire
    let rules = load("anti_analysis", "process-list-scan");
    let feats = one_fn(vec![], vec!["CreateToolhelp32Snapshot"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

// ─── 16B: injection ──────────────────────────────────────────────────────────

#[test]
fn injection_createremotethread_fires() {
    let rules = load("injection", "createremotethread");
    let feats = one_fn(vec![], vec!["CreateRemoteThread"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_createremotethread_no_fire() {
    let rules = load("injection", "createremotethread");
    let feats = one_fn(vec![], vec!["CreateThread"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_virtualallocex_writeprocessmemory_fires() {
    let rules = load("injection", "virtualallocex-writeprocessmemory");
    let feats = one_fn(vec![], vec!["VirtualAllocEx", "WriteProcessMemory"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_virtualallocex_writeprocessmemory_no_fire() {
    // only one of the two APIs — should not fire
    let rules = load("injection", "virtualallocex-writeprocessmemory");
    let feats = one_fn(vec![], vec!["VirtualAllocEx"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_setwindowshookex_fires() {
    let rules = load("injection", "setwindowshookex");
    let feats = one_fn(vec![], vec!["SetWindowsHookExA"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_setwindowshookex_no_fire() {
    let rules = load("injection", "setwindowshookex");
    let feats = one_fn(vec![], vec!["UnhookWindowsHookEx"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_queueuserapc_fires() {
    let rules = load("injection", "queueuserapc");
    let feats = one_fn(vec![], vec!["QueueUserAPC"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_queueuserapc_no_fire() {
    let rules = load("injection", "queueuserapc");
    let feats = empty_feats();
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_ntmapviewofsection_fires() {
    let rules = load("injection", "ntmapviewofsection");
    let feats = one_fn(vec![], vec!["NtMapViewOfSection"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_ntmapviewofsection_no_fire() {
    let rules = load("injection", "ntmapviewofsection");
    let feats = one_fn(vec![], vec!["NtCreateSection"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_process_hollowing_fires() {
    let rules = load("injection", "process-hollowing");
    let feats = one_fn(
        vec![],
        vec!["CreateProcessA", "NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
        vec![],
    );
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_process_hollowing_no_fire() {
    // missing SetThreadContext + ResumeThread
    let rules = load("injection", "process-hollowing");
    let feats = one_fn(
        vec![],
        vec!["CreateProcessA", "NtUnmapViewOfSection", "WriteProcessMemory"],
        vec![],
    );
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_reflective_loader_fires_on_export_name() {
    let rules = load("injection", "reflective-loader");
    let feats = one_fn(vec![], vec![], vec!["ReflectiveLoader"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_reflective_loader_no_fire() {
    let rules = load("injection", "reflective-loader");
    let feats = one_fn(vec![], vec!["LoadLibraryA"], vec!["user32.dll"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn injection_thread_hijack_fires() {
    let rules = load("injection", "thread-hijack");
    let feats = one_fn(vec![], vec!["GetThreadContext", "SetThreadContext"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn injection_thread_hijack_no_fire() {
    // only GetThreadContext — read-only, no hijack
    let rules = load("injection", "thread-hijack");
    let feats = one_fn(vec![], vec!["GetThreadContext"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}
