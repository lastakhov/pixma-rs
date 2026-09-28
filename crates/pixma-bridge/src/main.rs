mod escl;
mod translate;

use std::collections::HashMap;
use std::net::{IpAddr, TcpListener as StdTcpListener};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::Router;
use clap::Parser;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use escl::AppState;
use pixma_protocol::discover::{self, Printer};

const ESCL_BASE_PORT: u16 = 8470;
/// How many ports past the base we may scan through when allocating per-scanner listeners.
const MAX_PORT_ATTEMPTS: u16 = 30;

#[derive(Parser)]
#[command(name = "pixma-bridge", version, about = "eSCL-to-CHMP bridge daemon")]
struct Args {
    /// Bridge only the printer at this IP (default: all discovered scan-capable printers)
    #[arg(long)]
    device: Option<IpAddr>,
}

/// Kills spawned dns-sd advertisers when dropped, including on panic-unwind paths.
struct DnsSdAdvertisers(Vec<std::process::Child>);

impl Drop for DnsSdAdvertisers {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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
    bail!("no free port in {start}..{}", start + MAX_PORT_ATTEMPTS);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("pixma-bridge: discovering Canon printers...");
    let printers = discover::find_printers(Duration::from_secs(10)).await?;
    let printers: Vec<Printer> = match args.device {
        Some(ip) => {
            let printer = printers
                .into_iter()
                .find(|p| p.ip == ip)
                .with_context(|| format!("no Canon printer found at {ip}"))?;
            if !printer.scan_capable {
                bail!("printer at {ip} does not advertise scan capability");
            }
            vec![printer]
        }
        None => {
            let capable: Vec<Printer> = printers.into_iter().filter(|p| p.scan_capable).collect();
            if capable.is_empty() {
                bail!("no scan-capable Canon printer found");
            }
            capable
        }
    };

    let display_names = unique_display_names(&printers);
    let mut dns_sd = DnsSdAdvertisers(Vec::new());
    let mut tasks = JoinSet::new();
    let mut next_port = ESCL_BASE_PORT;

    for (printer, display_name) in printers.iter().zip(&display_names) {
        let std_listener = bind_listener(next_port)?;
        let port = std_listener.local_addr()?.port();
        next_port = port + 1;

        let (scan_done_tx, scan_done_rx) = tokio::sync::watch::channel(());
        let state = AppState {
            uuid: scanner_uuid(printer),
            printer_model: if printer.model.is_empty() {
                display_name.clone()
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

        // Advertise eSCL service via macOS dns-sd (more reliable than mdns-sd crate).
        // One _uscan._tcp service per physical scanner, named after the printer.
        let child = Command::new("dns-sd")
            .args([
                "-R",
                display_name,
                "_uscan._tcp",
                "local.",
                &port.to_string(),
                "txtvers=1",
                "vers=2.0",
                &format!("ty={}", state.printer_model),
                "rs=eSCL",
                "pdl=image/jpeg",
                "cs=color,grayscale",
                "is=platen",
                &format!("uuid={}", state.uuid),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("spawning dns-sd for {display_name}"))?;
        dns_sd.0.push(child);

        eprintln!(
            "pixma-bridge: '{display_name}' ({}) at {} -> eSCL on port {port}",
            printer.ip, printer.model
        );

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
        tasks.spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("pixma-bridge: eSCL server error: {e}");
            }
        });
    }

    eprintln!(
        "pixma-bridge: advertising {} eSCL scanner(s), base port {ESCL_BASE_PORT}",
        printers.len()
    );

    // Serve until interrupted (launchctl unload sends SIGTERM), then let
    // DnsSdAdvertisers::drop kill the dns-sd advertisers.
    tokio::select! {
        _ = shutdown_signal() => {
            eprintln!("pixma-bridge: shutting down");
        }
        Some(res) = tasks.join_next() => {
            let _ = res;
            bail!("eSCL server terminated unexpectedly");
        }
    }

    tasks.abort_all();
    Ok(())
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
}
