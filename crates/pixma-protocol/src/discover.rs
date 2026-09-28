// crates/pixma-protocol/src/discover.rs
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent};

use crate::bjnp::udp;
use crate::error::PixmaError;

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

/// Discover Canon printers using mDNS. Extracts model from TXT records,
/// then optionally probes BJNP for the full IEEE 1284 identity string.
pub async fn find_printers(timeout: Duration) -> Result<Vec<Printer>, PixmaError> {
    let mut printers = Vec::new();

    let mdns = ServiceDaemon::new().map_err(|e| PixmaError::Protocol(e.to_string()))?;
    let receiver = mdns
        .browse("_ipp._tcp.local.")
        .map_err(|e| PixmaError::Protocol(e.to_string()))?;

    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let remaining = deadline - std::time::Instant::now();
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let name = info.get_fullname().to_lowercase();
                if !name.contains("canon") {
                    continue;
                }
                if let Some(ip) = info.get_addresses_v4().into_iter().next() {
                    // Instance name is the part before the service type in the
                    // fullname, e.g. "Canon G3010 series._ipp._tcp.local.".
                    let name = info
                        .get_fullname()
                        .split("._")
                        .next()
                        .unwrap_or_default()
                        .to_string();

                    // Get model from mDNS TXT records (more reliable than BJNP)
                    let model = info
                        .get_property_val_str("ty")
                        .or_else(|| info.get_property_val_str("usb_MDL"))
                        .unwrap_or("Unknown Canon")
                        .to_string();

                    let scan_capable = info
                        .get_property_val_str("Scan")
                        .is_some_and(|v| v == "T");

                    // Try BJNP identity probe (may not respond on all models)
                    let bjnp_addr = SocketAddr::new(IpAddr::V4(ip), udp::BJNP_SCAN_PORT);
                    let identity = udp::get_identity(bjnp_addr).await.ok();

                    printers.push(Printer {
                        name,
                        model,
                        ip: IpAddr::V4(ip),
                        mac: None,
                        identity,
                        scan_capable,
                    });
                }
            }
            Err(_) => break,
            _ => {}
        }
    }

    let _ = mdns.shutdown();

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
