// crates/pixma-protocol/src/discover.rs
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use tokio::net::TcpStream;

use crate::bjnp::udp;
use crate::error::PixmaError;

/// Short TCP probe — CHMP scans/prints use port 80 on the printer.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(2);

const IPP_SERVICE: &str = "_ipp._tcp.local.";

/// A Canon printer found on the network.
#[derive(Debug, Clone)]
pub struct Printer {
    /// mDNS instance name, e.g. "Canon G3010 series" — unique per device on
    /// the network (printers rename themselves to "... (2)" on conflict).
    pub name: String,
    pub model: String,
    pub ip: IpAddr,
    /// Bonjour host target from the _ipp._tcp SRV record (e.g. `Canon-ab12cd.local`).
    pub hostname: Option<String>,
    pub mac: Option<[u8; 6]>,
    pub identity: Option<String>,
    pub scan_capable: bool,
}

/// Strip a trailing `.local` (and optional dot) from an mDNS host target.
pub fn host_label(hostname: &str) -> &str {
    hostname
        .trim_end_matches('.')
        .strip_suffix(".local")
        .unwrap_or(hostname)
}

impl Printer {
    /// Human-facing label: mDNS instance name plus host name or IP so identical
    /// models (USB share vs Wi‑Fi, or two units on the LAN) stay distinct.
    pub fn display_name(&self) -> String {
        let tag = self
            .hostname
            .as_deref()
            .map(host_label)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| self.ip.to_string());
        format!("{} ({tag})", self.name)
    }

    /// Serial number parsed from the BJNP IEEE 1284 identity string (`SER:...`).
    pub fn serial(&self) -> Option<&str> {
        self.identity
            .as_deref()?
            .split(';')
            .find_map(|kv| kv.strip_prefix("SER:"))
    }
}

fn primary_ip(info: &ResolvedService) -> Option<IpAddr> {
    for scoped in info.get_addresses() {
        let ip = scoped.to_ip_addr();
        if ip.is_ipv4() {
            return Some(ip);
        }
    }
    info.get_addresses().iter().next().map(|scoped| scoped.to_ip_addr())
}

fn printer_from_mdns(info: &ResolvedService) -> Option<Printer> {
    if !info.is_valid() {
        return None;
    }
    let fullname = info.get_fullname().to_lowercase();
    if !fullname.contains("canon") {
        return None;
    }
    let ip = primary_ip(info)?;
    let name = info
        .get_fullname()
        .split("._")
        .next()
        .unwrap_or_default()
        .to_string();
    let model = info
        .get_property_val_str("ty")
        .or_else(|| info.get_property_val_str("usb_MDL"))
        .unwrap_or("Unknown Canon")
        .to_string();
    let scan_capable = info
        .get_property_val_str("Scan")
        .is_some_and(|v| v == "T");
    let hostname = {
        let h = info.get_hostname();
        if h.is_empty() {
            None
        } else {
            Some(h.to_string())
        }
    };
    Some(Printer {
        name,
        model,
        ip,
        hostname,
        mac: None,
        identity: None,
        scan_capable,
    })
}

fn identity_implies_scan(identity: &str) -> bool {
    identity.contains("CHMP") || identity.contains("IVEC")
}

async fn attach_identity(mut printer: Printer) -> Printer {
    let bjnp_addr = SocketAddr::new(printer.ip, udp::BJNP_SCAN_PORT);
    if let Ok(identity) = udp::get_identity(bjnp_addr).await {
        printer.identity = Some(identity.clone());
        if !printer.scan_capable && identity_implies_scan(&identity) {
            printer.scan_capable = true;
        }
    }
    printer
}

/// Quick liveness check for a known printer IP (used by the bridge so one
/// offline device does not mark healthy bridged scanners as "missing").
pub async fn is_reachable(ip: IpAddr) -> bool {
    let addr = format!("{ip}:80");
    tokio::time::timeout(REACHABILITY_TIMEOUT, TcpStream::connect(&addr))
        .await
        .is_ok_and(|result| result.is_ok())
}

/// Wait until the printer answers on TCP/80 (wakes a sleeping printer). Used
/// before CHMP scan when the unit may be in power-save mode.
pub async fn wait_reachable(
    ip: IpAddr,
    attempts: u32,
    interval: Duration,
) -> Result<(), PixmaError> {
    for i in 0..attempts {
        if is_reachable(ip).await {
            if i > 0 {
                eprintln!("pixma: printer at {ip} reachable after {i} probe(s)");
            }
            return Ok(());
        }
        if i + 1 < attempts {
            tokio::time::sleep(interval).await;
        }
    }
    Err(PixmaError::Protocol(format!(
        "printer at {ip} not reachable after {attempts} attempts (offline or asleep)"
    )))
}

fn shutdown_mdns(mdns: &ServiceDaemon) {
    if let Ok(rx) = mdns.shutdown() {
        let _ = rx.recv_timeout(Duration::from_secs(2));
    }
}

/// Long-lived mDNS handle for repeated discovery (e.g. the bridge poll loop).
///
/// `ServiceDaemon::new()` spawns a background thread; dropping the daemon
/// without [`ServiceDaemon::shutdown`] leaks that thread. A one-shot caller
/// can use [`find_printers`]; daemons that poll should hold a [`Discoverer`].
pub struct Discoverer {
    mdns: ServiceDaemon,
}

impl Discoverer {
    pub fn new() -> Result<Self, PixmaError> {
        ServiceDaemon::new()
            .map_err(|e| PixmaError::Protocol(e.to_string()))
            .map(|mdns| Self { mdns })
    }

    pub async fn find_printers(&self, timeout: Duration) -> Result<Vec<Printer>, PixmaError> {
        find_printers_with(&self.mdns, timeout).await
    }
}

impl Drop for Discoverer {
    fn drop(&mut self) {
        shutdown_mdns(&self.mdns);
    }
}

/// Discover Canon printers using mDNS. Extracts model from TXT records,
/// then optionally probes BJNP for the full IEEE 1284 identity string.
///
/// mDNS browsing and BJNP identity probes are kept separate so a slow or
/// dead printer cannot block discovery of the rest (probes run in parallel).
pub async fn find_printers(timeout: Duration) -> Result<Vec<Printer>, PixmaError> {
    let discoverer = Discoverer::new()?;
    discoverer.find_printers(timeout).await
}

async fn find_printers_with(mdns: &ServiceDaemon, timeout: Duration) -> Result<Vec<Printer>, PixmaError> {
    let receiver = mdns
        .browse(IPP_SERVICE)
        .map_err(|e| PixmaError::Protocol(e.to_string()))?;

    let mut stubs = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let remaining = deadline - std::time::Instant::now();
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(printer) = printer_from_mdns(info.as_ref()) {
                    stubs.push(printer);
                }
            }
            Err(_) => break,
            _ => {}
        }
    }

    let _ = mdns.stop_browse(IPP_SERVICE);

    let probe_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut join_set = tokio::task::JoinSet::new();
    for stub in stubs {
        join_set.spawn(attach_identity(stub));
    }
    let mut printers = Vec::new();
    loop {
        match tokio::time::timeout_at(probe_deadline, join_set.join_next()).await {
            Ok(Some(Ok(printer))) => printers.push(printer),
            Ok(Some(Err(e))) => eprintln!("pixma discover: identity probe task failed: {e}"),
            Ok(None) | Err(_) => break,
        }
    }

    printers.sort_by_key(|p| p.ip.to_string());
    printers.dedup_by_key(|p| p.ip.to_string());

    Ok(printers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printer(identity: Option<&str>) -> Printer {
        Printer {
            name: "Canon G3010 series".into(),
            model: "Canon PIXMA G3010".into(),
            ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            hostname: Some("Canon-g3010.local.".into()),
            mac: None,
            identity: identity.map(String::from),
            scan_capable: true,
        }
    }

    #[test]
    fn display_name_uses_hostname() {
        let p = printer(None);
        assert_eq!(p.display_name(), "Canon G3010 series (Canon-g3010)");
    }

    #[test]
    fn display_name_falls_back_to_ip() {
        let mut p = printer(None);
        p.hostname = None;
        assert_eq!(
            p.display_name(),
            format!("Canon G3010 series ({})", p.ip)
        );
    }

    #[test]
    fn serial_from_identity() {
        let p = printer(Some(
            "MFG:Canon;CMD:BJL,BJRaster3;MDL:G3010 series;SER:9Z2K1;CLS:PRINTER",
        ));
        assert_eq!(p.serial(), Some("9Z2K1"));
    }

    #[test]
    fn serial_absent() {
        assert_eq!(printer(None).serial(), None);
        assert_eq!(printer(Some("MFG:Canon;MDL:G3010 series")).serial(), None);
    }
}
