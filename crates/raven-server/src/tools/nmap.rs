use raven_core::{config::RavenConfig, executor, safety};
use rmcp::{
    Peer, RoleServer,
    model::{CallToolResult, Content},
    schemars,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NmapRequest {
    #[schemars(description = "Target IP, hostname, or CIDR range")]
    pub target: String,
    #[schemars(description = "Port spec (e.g. '80,443' or '1-1000')")]
    pub ports: Option<String>,
    #[schemars(description = "Scan type: 'quick', 'service', 'os'")]
    pub scan_type: Option<String>,
}

pub async fn run(
    config: &RavenConfig,
    req: NmapRequest,
    peer: Option<Peer<RoleServer>>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    safety::validate_target(&req.target).map_err(crate::error::to_mcp)?;

    let _ticker = peer.map(|p| {
        crate::progress::ProgressTicker::start(p, "nmap".into(), req.target.clone())
    });

    // OS detection requires root privileges
    // SAFETY: geteuid is a trivial read-only syscall with no invariants
    if req.scan_type.as_deref() == Some("os") && unsafe { libc::geteuid() } != 0 {
        return Err(rmcp::ErrorData::invalid_params(
            "scan_type 'os' requires root privileges (nmap -O needs raw sockets)",
            None,
        ));
    }

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

/// Parse nmap XML output into a structured text summary.
pub fn parse_nmap_xml(xml: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();

    if root.tag_name().name() != "nmaprun" {
        return None;
    }

    let mut output = String::new();

    // Extract scan info
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

        // Ports
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
            }
        }

        // OS detection results
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

    // Run stats
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
}
