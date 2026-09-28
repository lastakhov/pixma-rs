mod escl;
mod translate;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, TcpListener as StdTcpListener};
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::Router;
use clap::Parser;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use escl::AppState;
use pixma_protocol::discover::{self, Printer};

const ESCL_BASE_PORT: u16 = 8470;
/// How many ports past the base we may scan through when allocating per-scanner listeners.
const MAX_PORT_ATTEMPTS: u16 = 30;
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// How often to re-scan the network for printers that appeared or went away.
const POLL_INTERVAL: Duration = Duration::from_secs(30);
/// Consecutive rounds a bridged scanner may be missing from discovery before
/// its eSCL service is withdrawn. Printers briefly asleep stay advertised;
/// long-gone ones disappear from Image Capture and return (same UUID) once
/// they are back.
const LOST_LIMIT: u32 = 10;

#[derive(Parser)]
#[command(name = "pixma-bridge", version, about = "eSCL-to-CHMP bridge daemon")]
struct Args {
    /// Bridge only the printer at this IP (default: all discovered scan-capable printers)
    #[arg(long)]
    device: Option<IpAddr>,
}

/// A scanner currently served by this daemon.
struct Bridged {
    printer: Printer,
    display_name: String,
    port: u16,
    server: JoinHandle<()>,
    dns_sd: Child,
}

/// Scanner display names for Bonjour: the printer's own mDNS name, made unique
/// with the serial number (or IP) when two identical models share a name.
fn unique_display_names(printers: &[Printer]) -> Vec<String> {
    printers
        .iter()
        .map(|p| {
            let duplicates = printers.iter().filter(|q| q.name == p.name).count();
            if duplicates < 2 {
                return p.name.clone();
            }
            match p.serial() {
                Some(serial) => format!("{} ({serial})", p.name),
                None => format!("{} (@ {})", p.name, p.ip),
            }
        })
        .collect()
}

/// Stable per-scanner UUID: derived from the serial (or name), so Image Capture
/// keeps seeing the same device across daemon restarts instead of a new one
/// each time.
fn scanner_uuid(printer: &Printer) -> String {
    let key = match printer.serial() {
        Some(serial) => format!("pixma-bridge/serial/{serial}"),
        None => format!("pixma-bridge/name/{}", printer.name),
    };
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, key.as_bytes()).to_string()
}

fn bind_listener(start: u16) -> Result<StdTcpListener> {
    for port in start..start + MAX_PORT_ATTEMPTS {
        match StdTcpListener::bind(("0.0.0.0", port)) {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e).with_context(|| format!("binding port {port}")),
        }
    }
    anyhow::bail!("no free port in {start}..{}", start + MAX_PORT_ATTEMPTS);
}

/// Register a `_uscan._tcp` Bonjour service pointing at our eSCL server.
fn advertise(display_name: &str, model: &str, port: u16, uuid: &str) -> Result<Child> {
    Command::new("dns-sd")
        .args([
            "-R",
            display_name,
            "_uscan._tcp",
            "local.",
            &port.to_string(),
            "txtvers=1",
            "vers=2.0",
            &format!("ty={model}"),
            "rs=eSCL",
            "pdl=image/jpeg",
            "cs=color,grayscale",
            "is=platen",
            &format!("uuid={uuid}"),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning dns-sd for {display_name}"))
}

/// Update per-scanner miss counters against the currently discovered set.
/// Pure bookkeeping, kept separate from the I/O for testing.
fn bump_misses(misses: &mut HashMap<IpAddr, u32>, found: &HashSet<IpAddr>) {
    for (addr, count) in misses.iter_mut() {
        if found.contains(addr) {
            *count = 0;
        }
        *count += 1;
    }
}

/// Scanners whose miss counter has passed the withdrawal threshold.
fn withdrawals(misses: &HashMap<IpAddr, u32>) -> Vec<IpAddr> {
    misses
        .iter()
        .filter(|(_, m)| **m > LOST_LIMIT)
        .map(|(ip, _)| *ip)
        .collect()
}

async fn serve(printer: &Printer, display_name: &str) -> Result<(u16, Bridged)> {
    let std_listener = bind_listener(ESCL_BASE_PORT)?;
    let port = std_listener.local_addr()?.port();

    let (scan_done_tx, scan_done_rx) = tokio::sync::watch::channel(());
    let state = AppState {
        uuid: scanner_uuid(printer),
        printer_model: if printer.model.is_empty() {
            display_name.to_string()
        } else {
            printer.model.clone()
        },
        printer_ip: printer.ip,
        scanning: Arc::new(AtomicBool::new(false)),
        active_job_id: Arc::new(Mutex::new(None)),
        jobs: Arc::new(Mutex::new(HashMap::new())),
        scan_done: scan_done_rx,
        scan_done_tx: Arc::new(scan_done_tx),
    };

    let dns_sd = advertise(display_name, &state.printer_model, port, &state.uuid)?;

    let app = Router::new()
        .route("/eSCL/ScannerCapabilities", get(escl::get_capabilities))
        .route("/eSCL/ScannerStatus", get(escl::get_status))
        .route("/eSCL/ScanJobs", post(escl::create_scan_job))
        .route(
            "/eSCL/ScanJobs/{job_id}/NextDocument",
            get(escl::get_next_document),
        )
        .route("/eSCL/ScanJobs/{job_id}", delete(escl::delete_scan_job))
        .with_state(state)
        // Catch-all fallback to log unhandled requests
        .fallback(|req: axum::extract::Request| async move {
            eprintln!("[escl] UNHANDLED: {} {}", req.method(), req.uri());
            StatusCode::NOT_FOUND
        });

    std_listener
        .set_nonblocking(true)
        .with_context(|| format!("setting port {port} non-blocking"))?;
    let listener =
        tokio::net::TcpListener::from_std(std_listener).with_context(|| "tokio listener")?;
    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("pixma-bridge: eSCL server error: {e}");
        }
    });

    Ok((port, Bridged {
        printer: printer.clone(),
        display_name: display_name.to_string(),
        port,
        server,
        dns_sd,
    }))
}

/// Reconcile what is on the network with what we are bridging: start newly
/// appeared scanners, withdraw long-gone ones, refresh names if a collision
/// appeared. `misses` persists across rounds so withdrawal only happens after
/// LOST_LIMIT consecutive bad discoveries.
async fn sync_bridges(
    servers: &mut HashMap<IpAddr, Bridged>,
    misses: &mut HashMap<IpAddr, u32>,
    found: Vec<Printer>,
) {
    let found_ips: HashSet<IpAddr> = found.iter().map(|p| p.ip).collect();

    // Names must stay unique across running and newly discovered scanners.
    let mut combined: Vec<Printer> = servers.values().map(|b| b.printer.clone()).collect();
    combined.extend(found.iter().filter(|p| !servers.contains_key(&p.ip)).cloned());
    let name_by_ip: HashMap<IpAddr, String> = unique_display_names(&combined)
        .into_iter()
        .zip(&combined)
        .map(|(name, p)| (p.ip, name))
        .collect();

    for printer in found {
        if servers.contains_key(&printer.ip) {
            continue;
        }
        let display_name = name_by_ip[&printer.ip].clone();
        match serve(&printer, &display_name).await {
            Ok((port, bridged)) => {
                eprintln!(
                    "pixma-bridge: bridging '{display_name}' ({}) at {} -> eSCL on port {port}",
                    printer.ip, printer.model
                );
                servers.insert(printer.ip, bridged);
                misses.insert(printer.ip, 0);
            }
            Err(e) => eprintln!("pixma-bridge: cannot bridge '{}': {e:#}", printer.name),
        }
    }

    // A new scanner with a duplicate name may force a rename of a running one.
    for (addr, bridged) in servers.iter_mut() {
        let wanted = name_by_ip[addr].clone();
        if wanted != bridged.display_name {
            eprintln!(
                "pixma-bridge: renaming '{} ({addr})' -> '{wanted}'",
                bridged.display_name
            );
            let _ = bridged.dns_sd.kill();
            let _ = bridged.dns_sd.wait();
            let model = if bridged.printer.model.is_empty() {
                wanted.clone()
            } else {
                bridged.printer.model.clone()
            };
            match advertise(&wanted, &model, bridged.port, &scanner_uuid(&bridged.printer)) {
                Ok(child) => {
                    bridged.dns_sd = child;
                    bridged.display_name = wanted;
                }
                Err(e) => eprintln!("pixma-bridge: re-advertise failed: {e:#}"),
            }
        }
    }

    bump_misses(misses, &found_ips);
    for addr in withdrawals(misses) {
        misses.remove(&addr);
        if let Some(mut bridged) = servers.remove(&addr) {
            eprintln!(
                "pixma-bridge: '{}' ({addr}) not seen for {} rounds, withdrawing",
                bridged.display_name, LOST_LIMIT
            );
            let _ = bridged.dns_sd.kill();
            let _ = bridged.dns_sd.wait();
            bridged.server.abort();
        }
    }
}

async fn find_scan_capable(device: Option<IpAddr>) -> Vec<Printer> {
    let printers = discover::find_printers(DISCOVER_TIMEOUT)
        .await
        .unwrap_or_default();
    let mut capable: Vec<Printer> = printers.into_iter().filter(|p| p.scan_capable).collect();

    // The same physical printer can answer under several IPs (mDNS records
    // flap between link-local and LAN addresses); it would be bridged twice.
    // Keep one entry per stable scanner identity.
    let mut seen_uuids = HashSet::new();
    capable.retain(|p| seen_uuids.insert(scanner_uuid(p)));

    match device {
        Some(ip) => capable.into_iter().filter(|p| p.ip == ip).collect(),
        None => capable,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!(
        "pixma-bridge: watching for Canon scanners (poll every {}s)",
        POLL_INTERVAL.as_secs()
    );

    let mut servers: HashMap<IpAddr, Bridged> = HashMap::new();
    let mut misses: HashMap<IpAddr, u32> = HashMap::new();
    let mut reported_empty = false;
    let mut shutdown = std::pin::pin!(shutdown_signal());

    loop {
        let found = find_scan_capable(args.device).await;

        if found.is_empty() && servers.is_empty() && !reported_empty {
            let where_ = match args.device {
                Some(ip) => format!(" at {ip}"),
                None => String::new(),
            };
            eprintln!(
                "pixma-bridge: no scan-capable Canon printer{where_} visible yet, retrying"
            );
            reported_empty = true;
        } else if !found.is_empty() {
            reported_empty = false;
        }

        if args.device.is_some() && found.is_empty() && !servers.is_empty() {
            eprintln!("pixma-bridge: configured --device printer is not visible");
        }

        sync_bridges(&mut servers, &mut misses, found).await;

        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("pixma-bridge: shutting down, {} scanner(s)", servers.len());
                for bridged in servers.values_mut() {
                    let _ = bridged.dns_sd.kill();
                    let _ = bridged.dns_sd.wait();
                    bridged.server.abort();
                }
                return Ok(());
            }
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn printer(name: &str, ip: u8, serial: Option<&str>) -> Printer {
        Printer {
            name: name.into(),
            model: "Canon PIXMA G3010".into(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip)),
            mac: None,
            identity: serial.map(|s| format!("MFG:Canon;MDL:G3010 series;SER:{s};CLS:PRINTER")),
            scan_capable: true,
        }
    }

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, octet))
    }

    #[test]
    fn distinct_names_left_alone() {
        let printers = vec![printer("Canon G3010 series", 50, None), printer("Study", 51, None)];
        let names = unique_display_names(&printers);
        assert_eq!(names, vec!["Canon G3010 series", "Study"]);
    }

    #[test]
    fn duplicate_names_get_serial_suffix() {
        let printers = vec![
            printer("Canon G3010 series", 50, Some("AAA1")),
            printer("Canon G3010 series", 51, Some("BBB2")),
        ];
        let names = unique_display_names(&printers);
        assert_eq!(
            names,
            vec!["Canon G3010 series (AAA1)", "Canon G3010 series (BBB2)"]
        );
    }

    #[test]
    fn duplicate_names_without_serial_fall_back_to_ip() {
        let printers = vec![printer("Canon G3010 series", 50, None), printer("Canon G3010 series", 51, None)];
        let names = unique_display_names(&printers);
        assert_eq!(
            names,
            vec!["Canon G3010 series (@ 192.168.1.50)", "Canon G3010 series (@ 192.168.1.51)"]
        );
    }

    #[test]
    fn uuid_stable_across_restarts_and_distinct_per_device() {
        let a = printer("Canon G3010 series", 50, Some("AAA1"));
        let a_restart = printer("Canon G3010 series", 77, Some("AAA1"));
        let b = printer("Canon G3010 series", 51, Some("BBB2"));
        assert_eq!(scanner_uuid(&a), scanner_uuid(&a_restart));
        assert_ne!(scanner_uuid(&a), scanner_uuid(&b));
    }

    #[test]
    fn misses_reset_when_seen_and_accumulate_when_not() {
        let mut misses = HashMap::from([(ip(50), 3), (ip(51), 3)]);
        let found = HashSet::from([ip(50)]);
        bump_misses(&mut misses, &found);
        assert_eq!(misses[&ip(50)], 1); // seen -> reset, then bumped to 1
        assert_eq!(misses[&ip(51)], 4); // unseen -> incremented

        for _ in 0..LOST_LIMIT {
            bump_misses(&mut misses, &HashSet::new());
        }
        // Both exceed the limit and are due for withdrawal.
        let mut withdrawn = withdrawals(&misses);
        withdrawn.sort();
        assert_eq!(withdrawn, vec![ip(50), ip(51)]);

        let mut fresh = HashMap::from([(ip(50), LOST_LIMIT)]);
        bump_misses(&mut fresh, &HashSet::from([ip(50)]));
        assert!(withdrawals(&fresh).is_empty());
    }
}
