//! Nmap port scanner handler with XML output parsing.
//!
//! Supports four scan types: `quick` (default, `-T4 -F`), `service` (`-sV`),
//! `os` (`-O`, requires root), and `vuln` (`-sV --script=vuln`). All output
//! is requested in XML format (`-oX -`) and parsed into a structured text
//! summary via [`parse_nmap_xml`].
//!
//! Falls back to raw text output if XML parsing fails (e.g. when nmap emits
//! warnings before the XML document).
//!
//! The `os` scan type checks for root privileges via `libc::geteuid()` before
//! launching, since nmap's `-O` requires raw sockets.

use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

/// MCP request schema for `run_nmap`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NmapRequest {
    #[schemars(description = "Target IP, hostname, or CIDR range")]
    pub target: String,
    #[schemars(description = "Port spec (e.g. '80,443' or '1-1000')")]
    pub ports: Option<String>,
    #[schemars(description = "Scan type: 'quick', 'service', 'os', 'vuln'")]
    pub scan_type: Option<String>,
}

/// Execute an nmap scan, parse XML output, and return structured results.
pub async fn run(
    config: &RavenConfig,
    req: NmapRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker =
        peer.map(|p| crate::progress::ProgressTicker::start(p, "nmap".into(), req.target.clone()));

    // OS detection requires root for raw sockets
    // SAFETY: geteuid is a trivial read-only syscall with no invariants
    if req.scan_type.as_deref() == Some("os") && unsafe { libc::geteuid() } != 0 {
        return Err(rmcp::ErrorData::invalid_params(
            "scan_type 'os' requires root privileges (nmap -O needs raw sockets)",
            None,
        ));
    }

    // Build arguments based on scan type preset
    let mut args: Vec<String> = match req.scan_type.as_deref() {
        Some("service") => vec!["-sV".into()],
        Some("os") => vec!["-O".into()],
        Some("vuln") => vec!["-sV".into(), "--script=vuln".into()],
        _ => vec!["-T4".into(), "-F".into()], // quick (default)
    };

    // Request XML output to stdout for structured parsing
    args.extend_from_slice(&["-oX".into(), "-".into()]);

    if let Some(ports) = req.ports {
        args.push("-p".into());
        args.push(ports.clone());
    }

    args.push(req.target);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = executor::run(config, "nmap", &arg_refs, None)
        .await
        .map_err(crate::error::to_mcp)?;

    // Try structured XML parsing; fall back to raw output on failure
    let structured = parse_nmap_xml(&result.stdout);
    let output = match structured {
        Some(summary) => {
            let mut out = summary;
            if let Some(ref warning) = result.warning {
                out.push_str(&format!("\n\n⚠ {warning}"));
            }
            out
        }
        None => crate::error::format_result("nmap", &result),
    };

    Ok(CallToolResult::success(vec![Content::text(output)]))
}

/// Compress multi-line script output to a single line with "+N more" suffix.
///
/// Keeps the first line (trimmed) and appends how many additional lines were
/// omitted. If the first line exceeds `max_len`, it is truncated with "…".
fn summarize_script_output(output: &str, max_len: usize) -> String {
    let lines: Vec<&str> = output
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return String::new();
    }
    let first = if lines[0].len() > max_len {
        format!("{}…", &lines[0][..max_len])
    } else {
        lines[0].to_string()
    };
    if lines.len() > 1 {
        format!("{first} (+{} more lines)", lines.len() - 1)
    } else {
        first
    }
}

/// Format an NSE `<script>` element into a compact one- or few-line summary.
///
/// Special handling for `vulners`: parses the nested `<table>/<elem>` structure
/// to extract CVE IDs and CVSS scores, showing only the top 5 by severity.
/// All other scripts use the `output` attribute, compressed via
/// [`summarize_script_output`].
fn format_nse_script(script: &roxmltree::Node) -> Option<String> {
    let id = script.attribute("id")?;

    if id == "vulners" {
        // Parse structured vulners output: <table key="cpe:..."><table><elem key="id">...</elem><elem key="cvss">...</elem></table>...</table>
        let mut cves: Vec<(String, f32)> = Vec::new();
        for outer_table in script.children().filter(|n| n.tag_name().name() == "table") {
            for entry in outer_table
                .children()
                .filter(|n| n.tag_name().name() == "table")
            {
                let cve_id = entry
                    .children()
                    .find(|e| e.tag_name().name() == "elem" && e.attribute("key") == Some("id"))
                    .and_then(|e| e.text());
                let cvss = entry
                    .children()
                    .find(|e| e.tag_name().name() == "elem" && e.attribute("key") == Some("cvss"))
                    .and_then(|e| e.text())
                    .and_then(|s| s.parse::<f32>().ok());
                if let (Some(id), Some(score)) = (cve_id, cvss) {
                    cves.push((id.to_string(), score));
                }
            }
        }
        if cves.is_empty() {
            // Fall back to output attribute if structured parsing found nothing
            let out = script.attribute("output").unwrap_or("");
            return Some(format!("  {id}: {}", summarize_script_output(out, 300)));
        }
        // Sort by CVSS descending, show top 5
        cves.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let top: Vec<String> = cves
            .iter()
            .take(5)
            .map(|(id, s)| format!("{id}({s})"))
            .collect();
        let summary = top.join(", ");
        let extra = if cves.len() > 5 {
            format!(" +{} more", cves.len() - 5)
        } else {
            String::new()
        };
        Some(format!("  vulners: {summary}{extra}"))
    } else {
        let out = script.attribute("output").unwrap_or("");
        if out.is_empty() {
            return None;
        }
        Some(format!("  {id}: {}", summarize_script_output(out, 300)))
    }
}

/// Collect and format all `<script>` children of a node into compact lines.
fn collect_scripts(parent: &roxmltree::Node) -> Vec<String> {
    parent
        .children()
        .filter(|n| n.tag_name().name() == "script")
        .filter_map(|s| format_nse_script(&s))
        .collect()
}

/// Parse nmap XML output (`-oX -`) into a human-readable text summary.
///
/// Extracts: command line, host addresses, port states with service/version,
/// NSE script results (per-port and host-level), OS detection matches (top 3),
/// and run statistics (elapsed time, host counts).
///
/// For `vulners` scripts, parses the structured CVE table and shows the top 5
/// entries by CVSS score. All other scripts are compressed to single-line
/// summaries.
///
/// If the input contains non-XML content before the XML document (e.g. nmap
/// warnings), the parser strips the prefix to find `<?xml` or `<nmaprun`.
///
/// Returns `None` if the input isn't valid nmap XML.
pub fn parse_nmap_xml(xml: &str) -> Option<String> {
    // Strip any non-XML prefix (nmap warnings, etc.)
    let xml = xml
        .find("<?xml")
        .or_else(|| xml.find("<nmaprun"))
        .map(|i| &xml[i..])
        .unwrap_or(xml);

    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..Default::default()
    };
    let doc = roxmltree::Document::parse_with_options(xml, opts).ok()?;
    let root = doc.root_element();

    if root.tag_name().name() != "nmaprun" {
        return None;
    }

    let mut output = String::new();

    if let Some(args) = root.attribute("args") {
        output.push_str(&format!("Command: {args}\n"));
    }

    for host in root.children().filter(|n| n.tag_name().name() == "host") {
        // Host address
        if let Some(addr) = host.children().find(|n| n.tag_name().name() == "address") {
            let ip = addr.attribute("addr").unwrap_or("unknown");
            let addr_type = addr.attribute("addrtype").unwrap_or("");
            output.push_str(&format!("\n── Host: {ip} ({addr_type}) ──\n"));
        }

        // Host status
        if let Some(status) = host.children().find(|n| n.tag_name().name() == "status") {
            let state = status.attribute("state").unwrap_or("unknown");
            output.push_str(&format!("Status: {state}\n"));
        }

        // Port table + per-port scripts
        let mut port_scripts: Vec<(String, Vec<String>)> = Vec::new();
        if let Some(ports) = host.children().find(|n| n.tag_name().name() == "ports") {
            output.push_str("\nPORT       STATE    SERVICE    VERSION\n");
            for port in ports.children().filter(|n| n.tag_name().name() == "port") {
                let proto = port.attribute("protocol").unwrap_or("?");
                let portid = port.attribute("portid").unwrap_or("?");

                let state = port
                    .children()
                    .find(|n| n.tag_name().name() == "state")
                    .and_then(|n| n.attribute("state"))
                    .unwrap_or("?");

                let (service_name, version) = port
                    .children()
                    .find(|n| n.tag_name().name() == "service")
                    .map(|svc| {
                        let name = svc.attribute("name").unwrap_or("?");
                        let product = svc.attribute("product").unwrap_or("");
                        let ver = svc.attribute("version").unwrap_or("");
                        let version_str = [product, ver]
                            .iter()
                            .filter(|s| !s.is_empty())
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" ");
                        (name, version_str)
                    })
                    .unwrap_or(("?", String::new()));

                output.push_str(&format!(
                    "{portid}/{proto:<4}  {state:<8} {service_name:<10} {version}\n"
                ));

                // Collect per-port scripts
                let scripts = collect_scripts(&port);
                if !scripts.is_empty() {
                    port_scripts.push((format!("{portid}/{proto}"), scripts));
                }
            }
        }

        // Print per-port script results
        if !port_scripts.is_empty() {
            output.push_str("\nScripts:\n");
            for (port_label, scripts) in &port_scripts {
                output.push_str(&format!(" {port_label}:\n"));
                for line in scripts {
                    output.push_str(&format!("{line}\n"));
                }
            }
        }

        // Host-level scripts (<hostscript>)
        if let Some(hostscript) = host
            .children()
            .find(|n| n.tag_name().name() == "hostscript")
        {
            let scripts = collect_scripts(&hostscript);
            if !scripts.is_empty() {
                output.push_str("\nHost scripts:\n");
                for line in &scripts {
                    output.push_str(&format!("{line}\n"));
                }
            }
        }

        // OS detection results (top 3 matches)
        for osmatch in host
            .children()
            .find(|n| n.tag_name().name() == "os")
            .into_iter()
            .flat_map(|os| os.children().filter(|n| n.tag_name().name() == "osmatch"))
            .take(3)
        {
            let name = osmatch.attribute("name").unwrap_or("?");
            let accuracy = osmatch.attribute("accuracy").unwrap_or("?");
            output.push_str(&format!("OS: {name} (accuracy: {accuracy}%)\n"));
        }
    }

    // Run statistics
    if let Some(runstats) = root.children().find(|n| n.tag_name().name() == "runstats") {
        if let Some(finished) = runstats
            .children()
            .find(|n| n.tag_name().name() == "finished")
        {
            let elapsed = finished.attribute("elapsed").unwrap_or("?");
            output.push_str(&format!("\nScan completed in {elapsed}s\n"));
        }
        if let Some(hosts) = runstats.children().find(|n| n.tag_name().name() == "hosts") {
            let up = hosts.attribute("up").unwrap_or("0");
            let down = hosts.attribute("down").unwrap_or("0");
            output.push_str(&format!("Hosts: {up} up, {down} down\n"));
        }
    }

    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_xml_extracts_host_and_ports() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun args="nmap -sV 10.0.0.1">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished elapsed="1.23"/>
    <hosts up="1" down="0"/>
  </runstats>
</nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        assert!(result.contains("10.0.0.1"));
        assert!(result.contains("22"));
        assert!(result.contains("ssh"));
        assert!(result.contains("OpenSSH 8.9"));
        assert!(result.contains("80"));
        assert!(result.contains("nginx"));
        assert!(result.contains("1.23s"));
        assert!(result.contains("1 up"));
    }

    #[test]
    fn parse_xml_with_os_detection() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
      <osmatch name="Linux 5.10" accuracy="90"/>
    </os>
  </host>
</nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        assert!(result.contains("Linux 5.4"));
        assert!(result.contains("95%"));
    }

    #[test]
    fn parse_malformed_xml_returns_none() {
        assert!(parse_nmap_xml("this is not xml at all").is_none());
        assert!(parse_nmap_xml("<unclosed>").is_none());
    }

    #[test]
    fn parse_wrong_root_tag_returns_none() {
        let xml = r#"<?xml version="1.0"?><other/>"#;
        assert!(parse_nmap_xml(xml).is_none());
    }

    #[test]
    fn parse_empty_nmaprun_returns_none() {
        let xml = r#"<?xml version="1.0"?><nmaprun/>"#;
        // No hosts, no runstats — output is empty
        assert!(parse_nmap_xml(xml).is_none());
    }

    #[test]
    fn parse_real_localhost_xml_with_doctype() {
        // Real nmap output from `nmap -T4 -F -oX - 127.0.0.1`
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.98 scan initiated as: nmap -T4 -F -oX - 127.0.0.1 -->
<nmaprun scanner="nmap" args="nmap -T4 -F -oX - 127.0.0.1" start="1773049936" version="7.98">
<scaninfo type="connect" protocol="tcp" numservices="100" services="7,9,13,21-23"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames/>
</hosthint>
<host starttime="1773049936" endtime="1773049936"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports><extraports state="closed" count="97">
<extrareasons reason="conn-refused" count="97" proto="tcp" ports="7,9,13"/>
</extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="631"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ipp" method="table" conf="3"/></port>
</ports>
<times srtt="94" rttvar="97" to="100000"/>
</host>
<runstats><finished time="1773049936" elapsed="0.02" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"#;
        let result = parse_nmap_xml(xml);
        println!("Result: {result:?}");
        assert!(result.is_some(), "Parser returned None on real nmap XML!");
        let text = result.unwrap();
        println!("--- Parsed output ---\n{text}");
        assert!(text.contains("127.0.0.1"));
        assert!(text.contains("22"));
        assert!(text.contains("ssh"));
    }

    #[test]
    fn parse_vuln_scan_with_scripts() {
        // Realistic vuln scan XML with vulners, slowloris, http-enum, cookie-flags
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script=vuln -p 80 10.0.0.1" start="1773050000" version="7.98">
<host starttime="1773050000" endtime="1773050120">
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <status state="up"/>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache" version="2.4.25"/>
      <script id="vulners" output="cpe:/a:apache:http_server:2.4.25:&#xa;  CVE-2017-9798  7.5&#xa;  CVE-2021-44790  9.8&#xa;  CVE-2019-0211  7.8">
        <table key="cpe:/a:apache:http_server:2.4.25">
          <table>
            <elem key="id">CVE-2021-44790</elem>
            <elem key="cvss">9.8</elem>
            <elem key="type">cve</elem>
          </table>
          <table>
            <elem key="id">CVE-2019-0211</elem>
            <elem key="cvss">7.8</elem>
            <elem key="type">cve</elem>
          </table>
          <table>
            <elem key="id">CVE-2017-9798</elem>
            <elem key="cvss">7.5</elem>
            <elem key="type">cve</elem>
          </table>
          <table>
            <elem key="id">CVE-2021-26691</elem>
            <elem key="cvss">7.5</elem>
            <elem key="type">cve</elem>
          </table>
          <table>
            <elem key="id">CVE-2020-11984</elem>
            <elem key="cvss">7.5</elem>
            <elem key="type">cve</elem>
          </table>
          <table>
            <elem key="id">CVE-2018-1312</elem>
            <elem key="cvss">6.8</elem>
            <elem key="type">cve</elem>
          </table>
          <table>
            <elem key="id">CVE-2017-15715</elem>
            <elem key="cvss">6.8</elem>
            <elem key="type">cve</elem>
          </table>
        </table>
      </script>
      <script id="http-slowloris-check" output="VULNERABLE:&#xa;  Slowloris DoS attack&#xa;    State: LIKELY VULNERABLE"/>
      <script id="http-enum" output="/icons/: Potentially interesting directory&#xa;/manual/: Web server manual"/>
      <script id="http-cookie-flags" output="/login.php: Set-Cookie: PHPSESSID - httponly flag not set"/>
    </port>
  </ports>
  <hostscript>
    <script id="clock-skew" output="mean: 0s, deviation: 0s, median: 0s"/>
  </hostscript>
</host>
<runstats>
  <finished elapsed="120.45"/>
  <hosts up="1" down="0"/>
</runstats>
</nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        println!("--- Vuln scan parsed output ---\n{result}");

        // Port table still works
        assert!(result.contains("80"));
        assert!(result.contains("Apache 2.4.25"));

        // Vulners: top 5 CVEs sorted by CVSS, with "+2 more"
        assert!(result.contains("vulners:"));
        assert!(result.contains("CVE-2021-44790(9.8)"));
        assert!(result.contains("CVE-2019-0211(7.8)"));
        assert!(result.contains("+2 more"));
        // 6th and 7th CVEs should NOT appear in summary
        assert!(!result.contains("CVE-2018-1312"));
        assert!(!result.contains("CVE-2017-15715"));

        // Other scripts compressed to single lines
        assert!(result.contains("http-slowloris-check:"));
        assert!(result.contains("http-enum:"));
        assert!(result.contains("http-cookie-flags:"));

        // Host-level scripts
        assert!(result.contains("Host scripts:"));
        assert!(result.contains("clock-skew:"));

        // Output should be compact — well under 1000 chars
        assert!(
            result.len() < 1200,
            "Parsed vuln output too large: {} chars",
            result.len()
        );
    }

    #[test]
    fn parse_xml_with_warning_prefix() {
        // nmap sometimes prints warnings before XML
        let xml = "WARNING: No targets were specified\n\
                   Starting Nmap 7.98\n\
                   <?xml version=\"1.0\"?>\n\
                   <nmaprun args=\"nmap -sV 10.0.0.1\">\n\
                   <host><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/></host>\n\
                   </nmaprun>";
        let result = parse_nmap_xml(xml);
        assert!(result.is_some(), "Should strip non-XML prefix");
        assert!(result.unwrap().contains("10.0.0.1"));
    }

    #[test]
    fn summarize_long_output() {
        let output = "Line one is here\nLine two\nLine three\nLine four";
        let summary = summarize_script_output(output, 300);
        assert!(summary.contains("Line one"));
        assert!(summary.contains("+3 more lines"));
    }
}
