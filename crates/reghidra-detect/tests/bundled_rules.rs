//! One synthetic-Features unit test per bundled rule.
//! For each rule we (a) build a Features that MUST fire it and (b) one that MUST NOT.

use reghidra_detect::*;
use std::collections::HashMap;

fn empty_feats() -> Features { Features::default() }

fn file_feats(strings: Vec<&str>) -> Features {
    Features {
        file: FileFeatures {
            strings: strings.into_iter().map(String::from).collect(),
            ..FileFeatures::default()
        },
        ..Features::default()
    }
}

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

fn file_feats_with_sections(sections: Vec<SectionInfo>) -> Features {
    Features {
        file: FileFeatures {
            sections,
            ..FileFeatures::default()
        },
        ..Features::default()
    }
}

fn file_feats_with_pe(sections: Vec<SectionInfo>, tls_callbacks: bool) -> Features {
    Features {
        file: FileFeatures {
            sections,
            pe: Some(PeFeatures {
                tls_callbacks,
                ..PeFeatures::default()
            }),
            ..FileFeatures::default()
        },
        ..Features::default()
    }
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

// ─── 16C: persistence ────────────────────────────────────────────────────────

#[test]
fn persistence_run_key_write_fires() {
    let rules = load("persistence", "run-key-write");
    let feats = one_fn(vec![], vec!["RegSetValueExA"],
        vec!["Software\\Microsoft\\Windows\\CurrentVersion\\Run"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn persistence_run_key_write_no_fire() {
    // has the API but not the key string
    let rules = load("persistence", "run-key-write");
    let feats = one_fn(vec![], vec!["RegSetValueExA"], vec!["HKEY_LOCAL_MACHINE"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn persistence_schtasks_shell_fires() {
    let rules = load("persistence", "schtasks-shell");
    let feats = one_fn(vec![], vec!["CreateProcessA"], vec!["schtasks /create /tn malware"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn persistence_schtasks_shell_no_fire() {
    // has CreateProcess but no schtasks string
    let rules = load("persistence", "schtasks-shell");
    let feats = one_fn(vec![], vec!["CreateProcessA"], vec!["cmd.exe"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn persistence_service_install_fires() {
    let rules = load("persistence", "service-install");
    let feats = one_fn(vec![], vec!["CreateServiceA"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn persistence_service_install_no_fire() {
    let rules = load("persistence", "service-install");
    let feats = one_fn(vec![], vec!["OpenServiceA"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn persistence_winlogon_notify_key_fires() {
    let rules = load("persistence", "winlogon-notify-key");
    let feats = one_fn(vec![], vec![], vec!["Winlogon\\Notify"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn persistence_winlogon_notify_key_no_fire() {
    let rules = load("persistence", "winlogon-notify-key");
    let feats = one_fn(vec![], vec![], vec!["Winlogon"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn persistence_ifeo_debugger_fires() {
    let rules = load("persistence", "ifeo-debugger");
    let feats = one_fn(vec![], vec![],
        vec!["Image File Execution Options"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn persistence_ifeo_debugger_no_fire() {
    let rules = load("persistence", "ifeo-debugger");
    let feats = one_fn(vec![], vec![], vec!["HKEY_LOCAL_MACHINE\\SOFTWARE"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn persistence_appinit_dlls_fires() {
    let rules = load("persistence", "appinit-dlls");
    let feats = one_fn(vec![], vec![], vec!["AppInit_DLLs"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn persistence_appinit_dlls_no_fire() {
    let rules = load("persistence", "appinit-dlls");
    let feats = one_fn(vec![], vec![], vec!["SYSTEM\\CurrentControlSet\\Services"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn persistence_wmi_event_subscription_fires() {
    let rules = load("persistence", "wmi-event-subscription");
    let feats = file_feats(vec!["__EventFilter", "CommandLineEventConsumer"]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 1);
}

#[test]
fn persistence_wmi_event_subscription_no_fire() {
    // only one of the two WMI class names
    let rules = load("persistence", "wmi-event-subscription");
    let feats = file_feats(vec!["__EventFilter"]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 0);
}

// ─── 16D: crypto ─────────────────────────────────────────────────────────────

#[test]
fn crypto_aes_sbox_textual_fires() {
    let rules = load("crypto", "aes-sbox-textual");
    let feats = one_fn(vec![], vec!["CryptAcquireContextA"], vec!["AES"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn crypto_aes_sbox_textual_no_fire() {
    // crypto API present but no AES/Rijndael string
    let rules = load("crypto", "aes-sbox-textual");
    let feats = one_fn(vec![], vec!["CryptAcquireContextA"], vec!["SHA256"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn crypto_rc4_ksa_pattern_fires() {
    let rules = load("crypto", "rc4-ksa-pattern");
    let mut bf = HashMap::new();
    bf.insert(0x1000, FunctionFeatures {
        name: "t".into(),
        apis: vec![],
        string_refs: vec![],
        mnemonics: vec!["xor".into(), "mov".into(), "add".into()],
        xref_in_count: 0,
        xref_out_count: 3,
    });
    let feats = Features { by_function: bf, ..Features::default() };
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn crypto_rc4_ksa_pattern_no_fire() {
    // mnemonic sequence present but xref_out too low
    let rules = load("crypto", "rc4-ksa-pattern");
    let mut bf = HashMap::new();
    bf.insert(0x1000, FunctionFeatures {
        name: "t".into(),
        apis: vec![],
        string_refs: vec![],
        mnemonics: vec!["xor".into(), "mov".into(), "add".into()],
        xref_in_count: 0,
        xref_out_count: 1,
    });
    let feats = Features { by_function: bf, ..Features::default() };
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn crypto_crypt32_full_api_chain_fires() {
    let rules = load("crypto", "crypt32-full-api-chain");
    let feats = one_fn(vec![],
        vec!["CryptAcquireContext", "CryptCreateHash", "CryptEncrypt"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn crypto_crypt32_full_api_chain_no_fire() {
    // missing CryptCreateHash
    let rules = load("crypto", "crypt32-full-api-chain");
    let feats = one_fn(vec![], vec!["CryptAcquireContext", "CryptEncrypt"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn crypto_bcrypt_aes_fires() {
    let rules = load("crypto", "bcrypt-aes");
    let feats = one_fn(vec![], vec!["BCryptOpenAlgorithmProvider"], vec!["AES"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn crypto_bcrypt_aes_no_fire() {
    // BCrypt API but no AES identifier string
    let rules = load("crypto", "bcrypt-aes");
    let feats = one_fn(vec![], vec!["BCryptOpenAlgorithmProvider"], vec!["ChaCha20"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn crypto_custom_xor_loop_fires() {
    let rules = load("crypto", "custom-xor-loop");
    let feats = one_fn(vec!["xor", "inc", "cmp", "jne"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn crypto_custom_xor_loop_no_fire() {
    let rules = load("crypto", "custom-xor-loop");
    let feats = one_fn(vec!["mov", "add", "ret"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

// ─── 16E: network ────────────────────────────────────────────────────────────

#[test]
fn network_winsock_connect_fires() {
    let rules = load("network", "winsock-connect");
    let feats = one_fn(vec![], vec!["WSAStartup", "connect"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn network_winsock_connect_no_fire() {
    // socket API but no connect
    let rules = load("network", "winsock-connect");
    let feats = one_fn(vec![], vec!["WSAStartup", "bind"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn network_wininet_http_fires() {
    let rules = load("network", "wininet-http");
    let feats = one_fn(vec![], vec!["InternetOpenA", "InternetConnect"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn network_wininet_http_no_fire() {
    // InternetOpen but neither InternetConnect nor HttpOpenRequest
    let rules = load("network", "wininet-http");
    let feats = one_fn(vec![], vec!["InternetOpenA", "InternetCloseHandle"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn network_winhttp_fires() {
    let rules = load("network", "winhttp");
    let feats = one_fn(vec![], vec!["WinHttpOpen", "WinHttpSendRequest"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn network_winhttp_no_fire() {
    // only WinHttpOpen without send
    let rules = load("network", "winhttp");
    let feats = one_fn(vec![], vec!["WinHttpOpen", "WinHttpReceiveResponse"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn network_dns_exfil_heuristic_fires() {
    let rules = load("network", "dns-exfil-heuristic");
    let feats = one_fn(vec![], vec!["DnsQuery_A"],
        vec!["dGhpcyBpcyBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5n"]);  // base64-ish 48 chars
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn network_dns_exfil_heuristic_no_fire() {
    // DnsQuery but no base64-like string
    let rules = load("network", "dns-exfil-heuristic");
    let feats = one_fn(vec![], vec!["DnsQuery_A"], vec!["example.com"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn network_raw_sockets_fires() {
    let rules = load("network", "raw-sockets");
    let feats = one_fn(vec![], vec!["socket"], vec!["SOCK_RAW"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn network_raw_sockets_no_fire() {
    // socket API but no raw socket indicator string
    let rules = load("network", "raw-sockets");
    let feats = one_fn(vec![], vec!["socket"], vec!["SOCK_STREAM"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

// ─── 16F: packers ────────────────────────────────────────────────────────────

#[test]
fn packers_upx_sections_fires() {
    let rules = load("packers", "upx-sections");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".UPX0".into(), size: 4096, entropy: 0.1, writable: false, executable: true },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 1);
}

#[test]
fn packers_upx_sections_no_fire() {
    let rules = load("packers", "upx-sections");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".text".into(), size: 4096, entropy: 5.0, writable: false, executable: true },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 0);
}

#[test]
fn packers_aspack_section_fires() {
    let rules = load("packers", "aspack-section");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".aspack".into(), size: 8192, entropy: 7.0, writable: false, executable: false },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 1);
}

#[test]
fn packers_aspack_section_no_fire() {
    let rules = load("packers", "aspack-section");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".data".into(), size: 4096, entropy: 3.5, writable: true, executable: false },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 0);
}

#[test]
fn packers_themida_tls_fires() {
    let rules = load("packers", "themida-tls");
    let feats = file_feats_with_pe(vec![
        SectionInfo { name: ".themida".into(), size: 65536, entropy: 7.9, writable: false, executable: true },
    ], true);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 1);
}

#[test]
fn packers_themida_tls_no_fire_missing_tls() {
    // .themida section but no TLS callbacks
    let rules = load("packers", "themida-tls");
    let feats = file_feats_with_pe(vec![
        SectionInfo { name: ".themida".into(), size: 65536, entropy: 7.9, writable: false, executable: true },
    ], false);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 0);
}

#[test]
fn packers_packed_high_entropy_fires() {
    let rules = load("packers", "packed-high-entropy");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".data".into(), size: 65536, entropy: 7.9, writable: true, executable: false },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 1);
}

#[test]
fn packers_packed_high_entropy_no_fire() {
    let rules = load("packers", "packed-high-entropy");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".text".into(), size: 32768, entropy: 6.5, writable: false, executable: true },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 0);
}

#[test]
fn packers_vmprotect_sections_fires() {
    let rules = load("packers", "vmprotect-sections");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".vmp0".into(), size: 131072, entropy: 7.8, writable: false, executable: true },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 1);
}

#[test]
fn packers_vmprotect_sections_no_fire() {
    let rules = load("packers", "vmprotect-sections");
    let feats = file_feats_with_sections(vec![
        SectionInfo { name: ".text".into(), size: 32768, entropy: 5.5, writable: false, executable: true },
    ]);
    assert_eq!(evaluate(&rules, &feats).file_hits.len(), 0);
}

// ─── 16G: suspicious_api ─────────────────────────────────────────────────────

#[test]
fn suspicious_api_manual_iat_resolution_fires() {
    let rules = load("suspicious_api", "manual-iat-resolution");
    let feats = one_fn(vec![], vec!["LoadLibraryA", "GetProcAddress"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn suspicious_api_manual_iat_resolution_no_fire() {
    // GetProcAddress alone, no LoadLibrary
    let rules = load("suspicious_api", "manual-iat-resolution");
    let feats = one_fn(vec![], vec!["GetProcAddress"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn suspicious_api_dynamic_api_resolution_fires() {
    let rules = load("suspicious_api", "dynamic-api-resolution");
    // 5 of the 8 listed API name strings present
    let feats = one_fn(vec![], vec![], vec![
        "VirtualAlloc", "VirtualProtect", "CreateThread", "WriteProcessMemory", "LoadLibraryA",
    ]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn suspicious_api_dynamic_api_resolution_no_fire() {
    // Only 4 strings — one short of threshold
    let rules = load("suspicious_api", "dynamic-api-resolution");
    let feats = one_fn(vec![], vec![], vec![
        "VirtualAlloc", "VirtualProtect", "CreateThread", "WriteProcessMemory",
    ]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn suspicious_api_shellcode_allocate_exec_fires() {
    let rules = load("suspicious_api", "shellcode-allocate-exec");
    let feats = one_fn(vec![], vec!["VirtualAlloc"], vec!["PAGE_EXECUTE_READWRITE"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn suspicious_api_shellcode_allocate_exec_no_fire() {
    // VirtualAlloc present but no RWX indicator
    let rules = load("suspicious_api", "shellcode-allocate-exec");
    let feats = one_fn(vec![], vec!["VirtualAlloc"], vec!["PAGE_READWRITE"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn suspicious_api_token_manipulation_fires() {
    let rules = load("suspicious_api", "token-manipulation");
    let feats = one_fn(vec![], vec!["OpenProcessToken", "AdjustTokenPrivileges"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn suspicious_api_token_manipulation_no_fire() {
    // OpenProcessToken alone — no adjustment or impersonation
    let rules = load("suspicious_api", "token-manipulation");
    let feats = one_fn(vec![], vec!["OpenProcessToken", "CloseHandle"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn suspicious_api_privilege_escalation_apis_fires() {
    let rules = load("suspicious_api", "privilege-escalation-apis");
    let feats = one_fn(vec![], vec!["AdjustTokenPrivileges"], vec!["SeDebugPrivilege"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn suspicious_api_privilege_escalation_apis_no_fire() {
    // SeDebugPrivilege string but no AdjustTokenPrivileges call
    let rules = load("suspicious_api", "privilege-escalation-apis");
    let feats = one_fn(vec![], vec!["LookupPrivilegeValueA"], vec!["SeDebugPrivilege"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

#[test]
fn suspicious_api_unhook_ntdll_fires() {
    let rules = load("suspicious_api", "unhook-ntdll");
    let feats = one_fn(vec!["syscall"], vec![], vec!["ntdll.dll"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn suspicious_api_unhook_ntdll_no_fire() {
    // ntdll.dll string but no direct syscall instruction
    let rules = load("suspicious_api", "unhook-ntdll");
    let feats = one_fn(vec!["call", "ret"], vec!["LoadLibraryA"], vec!["ntdll.dll"]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}

// ─── parse-all sanity ────────────────────────────────────────────────────────

#[test]
fn every_bundled_rulefile_parses() {
    for af in available_bundled_rulefiles() {
        let src = bundled_rule_contents(&af.path).unwrap();
        parse_rules_from_str(src, &af.path)
            .unwrap_or_else(|e| panic!("{} failed to parse: {e}", af.path));
    }
}
