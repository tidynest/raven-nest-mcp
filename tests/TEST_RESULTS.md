# Raven-Nest-MCP Unit & Integration Test Results

**Date:** 2026-06-22
**Toolchain:** Rust stable
**Command:** `cargo test --workspace`

## Summary

| Crate | Tests | Pass | Fail |
|-------|------:|-----:|-----:|
| raven-core | 86 | 86 | 0 |
| raven-report | 54 | 54 | 0 |
| raven-server | 144 | 144 | 0 |
| integration | 10 | 10 | 0 |
| **Total** | **294** | **294** | **0** |

**Result:** All 294 tests pass.

> The per-module enumeration below is the 2026-03-29 baseline (179 tests). The
> +115 tests added by the hardening campaign (recon tools, engagement, scope,
> audit, report formats, auto-extract) are counted in the summary above but not
> itemized here — regenerate the full list with `cargo test --workspace -- --list`.

---

## raven-core (49 tests)

### config (11 tests)
- `context_budget_zero_uses_defaults`
- `context_budget_derives_caps`
- `default_config_has_expected_tools`
- `network_config_defaults_to_none`
- `load_returns_error_on_missing_file`
- `resolve_tool_binary_falls_back_to_bare_name`
- `resolve_tool_binary_uses_custom_path`
- `timeout_for_falls_back_to_default`
- `timeout_for_returns_tool_specific_value`
- `network_config_parses_from_toml`
- `load_returns_error_on_malformed_toml`

### executor (1 test)
- `proxy_env_vars_set_on_command`

### msf_client (5 tests)
- `clear_confirmation_resets`
- `base_url_ssl`
- `confirmation_different_hash_resets`
- `base_url_no_ssl`
- `confirmation_gate_requires_double_call`

### safety (24 tests)
- `allowlist_rejects_unlisted_tool`
- `allowlist_accepts_listed_tool`
- `target_accepts_cidr_v6`
- `target_accepts_host_port`
- `target_accepts_ipv4`
- `target_accepts_hostname`
- `target_accepts_ipv6`
- `target_rejects_empty`
- `target_rejects_invalid_host_port`
- `target_allows_url_query_ampersand`
- `target_accepts_http_url`
- `target_rejects_ipv4_cidr_over_32`
- `target_rejects_ipv6_cidr_over_128`
- `target_rejects_metacharacters_in_url_host_path`
- `target_rejects_shell_metacharacters`
- `target_accepts_cidr_v4`
- `target_rejects_unsupported_scheme`
- `truncate_exact_boundary`
- `truncate_handles_empty_string`
- `truncate_handles_multibyte_utf8`
- `truncate_mixed_multibyte`
- `target_accepts_https_url`
- `truncate_preserves_head_and_tail`
- `truncate_returns_short_output_unchanged`

### scan_manager (8 tests)
- `default_args_nmap_builds_quick_scan`
- `default_args_nuclei_builds_silent_scan`
- `default_args_unknown_tool_appends_target`
- `scan_output_memory_size`
- `scan_status_info_none_output_for_running`
- `scan_status_info_tracks_elapsed_and_output`
- `spill_threshold_is_one_megabyte`
- `scan_output_disk_size`

---

## raven-report (18 tests)

### markdown (8 tests)
- `report_empty_findings`
- `report_contains_title_and_summary_table`
- `report_finding_numbering`
- `report_has_toc_methodology_tools`
- `report_includes_optional_fields`
- `report_includes_owasp_category`
- `report_omits_absent_optional_fields`
- `report_severity_counts_are_correct`

### store (10 tests)
- `delete_nonexistent`
- `delete_existing`
- `insert_and_get`
- `corrupted_file_skipped`
- `list_sorted_by_severity`
- `persistence_survives_delete`
- `persistence_round_trip`
- `load_all_returns_sorted`
- `migration_from_legacy_format`
- `unlimited_findings`

---

## raven-server (104 tests)

### budget (15 tests)
- `disabled_budget_returns_full_mode`
- `budget_shrinks_with_usage`
- `exhausted_budget_detected`
- `enabled_budget_starts_full`
- `mode_escalates_to_compact`
- `mode_escalates_to_minimal`
- `per_call_allocation_divides_fairly`
- `scale_cap_compact_mode`
- `scale_cap_disabled_returns_full`
- `scale_cap_full_mode`
- `scale_cap_minimal_mode`
- `status_line_absent_when_disabled`
- `status_line_present_when_enabled`
- `truncate_short_text_unchanged`
- `truncate_long_text_preserves_head_and_tail`

### tools::dalfox (3 tests)
- `parse_dalfox_empty_returns_none`
- `parse_dalfox_extracts_findings`
- `parse_dalfox_caps_at_20`

### tools::dnsrecon (4 tests)
- `parse_dnsrecon_empty_returns_none`
- `parse_dnsrecon_handles_text_prefix`
- `parse_dnsrecon_extracts_records`
- `parse_dnsrecon_caps_at_30`

### tools::enum4linux_ng (4 tests)
- `parse_caps_items_per_section`
- `parse_multiple_sections`
- `parse_empty_returns_none`
- `parse_info_markers_included`

### tools::feroxbuster (4 tests)
- `parse_feroxbuster_all_404s_returns_none`
- `parse_feroxbuster_empty_returns_none`
- `parse_feroxbuster_extracts_urls`
- `parse_feroxbuster_filters_404s`

### tools::ffuf (3 tests)
- `parse_ffuf_empty_returns_none`
- `parse_ffuf_no_results_returns_none`
- `parse_ffuf_extracts_results`

### tools::findings (4 tests)
- `parse_severity_case_insensitive`
- `parse_severity_rejects_invalid`
- `parse_severity_valid_values`
- `parse_severity_error_message`

### tools::http (7 tests)
- `strip_html_collapses_whitespace`
- `strip_html_decodes_entities`
- `strip_html_removes_comments`
- `strip_html_removes_scripts_and_styles`
- `strip_html_decodes_extended_entities`
- `strip_html_inserts_newlines_for_blocks`
- `strip_html_decodes_numeric_entities`

### tools::hydra (3 tests)
- `parse_hydra_no_creds_returns_summary`
- `parse_hydra_extracts_credentials`
- `parse_hydra_empty_returns_none`

### tools::john (3 tests)
- `parse_john_empty_returns_none`
- `parse_john_no_cracked`
- `parse_john_extracts_cracked`

### tools::lenient (5 tests)
- `accepts_missing`
- `accepts_null`
- `rejects_invalid_string`
- `accepts_number`
- `accepts_string`

### tools::masscan (3 tests)
- `parse_masscan_empty_returns_none`
- `parse_masscan_extracts_ports`
- `parse_masscan_no_ports_returns_none`

### tools::msf_exploit (1 test)
- `hash_is_deterministic`

### tools::msf_search (2 tests)
- `parse_empty_results`
- `parse_module_results`

### tools::msf_post (1 test)
- `request_struct_compiles`

### tools::msf_module_info (1 test)
- `parse_info_basic`

### tools::msf_sessions (3 tests)
- `blocked_commands`
- `parse_empty_sessions`
- `parse_sessions_with_entries`

### tools::nikto (4 tests)
- `cookie_uses_add_header_flag`
- `parse_nikto_empty_returns_none`
- `parse_nikto_rejects_help_text`
- `parse_nikto_extracts_findings`

### tools::nmap (9 tests)
- `parse_malformed_xml_returns_none`
- `parse_empty_nmaprun_returns_none`
- `parse_wrong_root_tag_returns_none`
- `summarize_long_output`
- `parse_xml_with_os_detection`
- `parse_xml_with_warning_prefix`
- `parse_valid_xml_extracts_host_and_ports`
- `parse_real_localhost_xml_with_doctype`
- `parse_vuln_scan_with_scripts`

### tools::nuclei (3 tests)
- `parse_nuclei_empty_returns_none`
- `parse_nuclei_extracts_findings`
- `parse_nuclei_skips_non_json_lines`

### tools::sqlmap (7 tests)
- `parse_sqlmap_critical_errors`
- `parse_sqlmap_empty_returns_none`
- `parse_sqlmap_not_injectable`
- `parse_sqlmap_timestamped_critical`
- `parse_sqlmap_extracts_injection_points`
- `strip_ansi_removes_escape_sequences`
- `parse_sqlmap_resumed_injection_points`

### tools::subfinder (3 tests)
- `parse_subfinder_empty_returns_none`
- `parse_subfinder_extracts_hosts`
- `parse_subfinder_caps_at_50`

### tools::testssl (3 tests)
- `parse_testssl_detects_vulnerable`
- `parse_testssl_empty_returns_none`
- `parse_testssl_extracts_vulns_and_certs`

### tools::whatweb (2 tests)
- `parse_whatweb_empty_returns_none`
- `parse_whatweb_extracts_tech_lines`

### tools::wpscan (5 tests)
- `enumerate_preset_mapping`
- `parse_wpscan_empty_returns_none`
- `parse_wpscan_minimal_output`
- `parse_wpscan_full_output`
- `parse_wpscan_caps_plugins_and_users`

### tools (root) (2 tests)
- `localhost_variants`
- `remote_targets`

---

## Integration Tests (8 tests)

File: `tests/integration_test.rs`

- `delete_nonexistent_finding`
- `list_findings_empty`
- `delete_existing_finding`
- `generate_report_produces_markdown`
- `save_and_retrieve_finding`
- `generate_report_uses_default_title`
- `save_finding_with_optional_fields`
- `list_findings_returns_sorted`

---

## Manual Test Results (historical)

See the manual test harness (`tests/manual_test_harness.py`) for live-target test results against bWAPP and OWASP Juice Shop. Last run: 2026-03-15 (297 tests, 93.9% pass rate, 5 findings documented).
