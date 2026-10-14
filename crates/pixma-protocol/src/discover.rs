// crates/pixma-protocol/src/discover.rs
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use tokio::net::TcpStream;

use crate::bjnp::udp;
use crate::error::PixmaError;

/// Short TCP probe — CHMP scans/prints use port 80 on the printer.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(2);

/// A Canon printer found on the network.
#[derive(Debug, Clone)]
pub struct Printer {
    /// mDNS instance name, e.g. "Canon G3010 series" — unique per device on
    /// the network (printers rename themselves to "... (2)" on conflict).
    pub name: String,
    pub model: String,
    pub ip: IpAddr,
    pub mac: Option<[u8; 6]>,
    pub identity: Option<String>,
    pub scan_capable: bool,
}

impl Printer {
    /// Serial number parsed from the BJNP IEEE 1284 identity string (`SER:...`).
    pub fn serial(&self) -> Option<&str> {
        self.identity
            .as_deref()?
            .split(';')
            .find_map(|kv| kv.strip_prefix("SER:"))
    }
}

fn printer_from_mdns(info: &ResolvedService) -> Option<Printer> {
    let fullname = info.get_fullname().to_lowercase();
    if !fullname.contains("canon") {
        return None;
    }
    let ip = info.get_addresses_v4().into_iter().next()?;
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
    Some(Printer {
        name,
        model,
        ip: IpAddr::V4(ip),
        mac: None,
        identity: None,
        scan_capable,
    })
}

async fn attach_identity(printer: Printer) -> Printer {
    let bjnp_addr = SocketAddr::new(printer.ip, udp::BJNP_SCAN_PORT);
    let identity = udp::get_identity(bjnp_addr).await.ok();
    Printer {
        identity,
        ..printer
    }
}

/// Quick liveness check for a known printer IP (used by the bridge so one
/// offline device does not mark healthy bridged scanners as "missing").
pub async fn is_reachable(ip: IpAddr) -> bool {
    let addr = format!("{ip}:80");
    tokio::time::timeout(REACHABILITY_TIMEOUT, TcpStream::connect(&addr))
        .await
        .is_ok_and(|result| result.is_ok())
}

/// Discover Canon printers using mDNS. Extracts model from TXT records,
/// then optionally probes BJNP for the full IEEE 1284 identity string.
///
/// mDNS browsing and BJNP identity probes are kept separate so a slow or
/// dead printer cannot block discovery of the rest (probes run in parallel).
pub async fn find_printers(timeout: Duration) -> Result<Vec<Printer>, PixmaError> {
    let mdns = ServiceDaemon::new().map_err(|e| PixmaError::Protocol(e.to_string()))?;
    let receiver = mdns
        .browse("_ipp._tcp.local.")
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

    let _ = mdns.shutdown();

    let mut join_set = tokio::task::JoinSet::new();
    for stub in stubs {
        join_set.spawn(attach_identity(stub));
    }
    let mut printers = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(printer) => printers.push(printer),
            Err(e) => {
                return Err(PixmaError::Protocol(format!("identity probe task: {e}")));
            }
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
            mac: None,
            identity: identity.map(String::from),
            scan_capable: true,
        }
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
