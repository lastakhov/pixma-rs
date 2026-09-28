use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use pixma_protocol::discover::{self, Printer};

const DISCOVER_TIMEOUT: Duration = Duration::from_secs(5);

/// One-line summary of a printer for selection lists.
fn summary(p: &Printer) -> String {
    let mut line = format!("{}  {}", p.name, p.ip);
    if let Some(serial) = p.serial() {
        line.push_str(&format!("  (serial {serial})"));
    }
    line
}

fn print_list(header: &str, printers: &[Printer]) {
    eprintln!("{header}");
    for (i, p) in printers.iter().enumerate() {
        eprintln!("  {}) {}", i + 1, summary(p));
    }
}

/// Resolve the device to operate on.
///
/// `spec` comes from `--device` and may be:
/// - an IP address — used as-is, no discovery round-trip;
/// - a case-insensitive substring of the printer's mDNS name, model or
///   IEEE 1284 identity (e.g. a serial number) — must match exactly one printer;
/// - omitted — discovery picks the single printer found, or asks the user to
///   choose when several are on the network.
pub async fn resolve(spec: Option<&str>, need_scan: bool) -> Result<Printer> {
    // Fast path: explicit IP, no discovery needed.
    if let Some(spec) = spec
        && let Ok(ip) = spec.parse::<IpAddr>()
    {
        return Ok(Printer {
            name: spec.to_string(),
            model: String::new(),
            ip,
            mac: None,
            identity: None,
            scan_capable: true,
        });
    }

    eprintln!("Searching for Canon printers...");
    let mut printers = discover::find_printers(DISCOVER_TIMEOUT).await?;
    if need_scan {
        printers.retain(|p| p.scan_capable);
    }
    if printers.is_empty() {
        bail!(
            "No Canon {} found. Check the printer is on the network, or use --device <ip>.",
            if need_scan { "scanner" } else { "printer" }
        );
    }

    match spec {
        None => pick_interactively(printers),
        Some(spec) => match_by_substring(spec, printers),
    }
}

fn match_by_substring(spec: &str, printers: Vec<Printer>) -> Result<Printer> {
    let needle = spec.to_lowercase();
    let (matched, rest): (Vec<Printer>, Vec<Printer>) = printers
        .into_iter()
        .partition(|p| {
            p.name.to_lowercase().contains(&needle)
                || p.model.to_lowercase().contains(&needle)
                || p.identity
                    .as_deref()
                    .is_some_and(|id| id.to_lowercase().contains(&needle))
        });

    match matched.len() {
        0 => {
            print_list("No Canon printer matches. Available printers:", &rest);
            bail!("--device '{spec}' matched nothing");
        }
        1 => Ok(matched.into_iter().next().unwrap()),
        _ => {
            print_list(&format!("--device '{spec}' is ambiguous, matched {} printers:", matched.len()), &matched);
            bail!("--device '{spec}' is ambiguous; use the IP address or a serial number");
        }
    }
}

fn pick_interactively(mut printers: Vec<Printer>) -> Result<Printer> {
    if printers.len() == 1 {
        let p = printers.into_iter().next().unwrap();
        eprintln!("Found: {} at {}", p.name, p.ip);
        return Ok(p);
    }

    // In a script (stdin not a TTY) a prompt would hang forever — fail with a list instead.
    if !std::io::stdin().is_terminal() {
        print_list("Multiple Canon printers found, pick one with --device:", &printers);
        bail!("Re-run with --device <ip> (or a unique part of the name / serial number)");
    }

    print_list("Multiple Canon printers found:", &printers);
    let default_idx = printers.len();
    loop {
        eprint!(
            "Select a printer [1-{}, default 1]: ",
            printers.len()
        );
        std::io::stderr().flush().ok();

        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim();

        let idx: usize = if answer.is_empty() {
            1
        } else {
            match answer.parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("Enter a number between 1 and {default_idx}");
                    continue;
                }
            }
        };
        if !(1..=default_idx).contains(&idx) {
            eprintln!("Enter a number between 1 and {default_idx}");
            continue;
        }
        return Ok(printers.swap_remove(idx - 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn printer(name: &str, ip: u8) -> Printer {
        Printer {
            name: name.into(),
            model: "Canon PIXMA G3010".into(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip)),
            mac: None,
            identity: None,
            scan_capable: true,
        }
    }

    #[test]
    fn single_printer_picked_without_prompt() {
        let p = pick_interactively(vec![printer("Canon G3010 series", 50)]).unwrap();
        assert_eq!(p.ip.to_string(), "192.168.1.50");
    }

    #[test]
    fn multiple_printers_without_tty_fail_with_list() {
        // Under `cargo test` stdin is not a terminal, same as in a script.
        let err = pick_interactively(vec![printer("office", 50), printer("home", 51)]).unwrap_err();
        assert!(err.to_string().contains("--device"));
    }

    #[test]
    fn substring_matches_exactly_one() {
        let p = match_by_substring(
            "office",
            vec![printer("office g3010", 50), printer("home g3010", 51)],
        )
        .unwrap();
        assert_eq!(p.ip.to_string(), "192.168.1.50");
    }

    #[test]
    fn ambiguous_substring_rejected() {
        let err = match_by_substring(
            "g3010",
            vec![printer("office g3010", 50), printer("home g3010", 51)],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }
}
