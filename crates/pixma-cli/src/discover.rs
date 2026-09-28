// crates/pixma-cli/src/discover.rs
use std::time::Duration;

use anyhow::Result;
use pixma_protocol::discover;

pub async fn run(timeout: u64) -> Result<()> {
    let printers = discover::find_printers(Duration::from_secs(timeout)).await?;

    if printers.is_empty() {
        println!("No Canon printers found.");
        return Ok(());
    }

    println!("Found {} Canon printer(s):", printers.len());
    println!();
    for p in &printers {
        println!("{}", p.name);
        if !p.model.is_empty() && !p.name.eq_ignore_ascii_case(&p.model) {
            println!("  Model: {}", p.model);
        }
        println!("  IP: {}", p.ip);
        if let Some(mac) = p.mac {
            let mac_str: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
            println!("  MAC: {}", mac_str.join(":"));
        }
        if let Some(serial) = p.serial() {
            println!("  Serial: {serial}");
        } else if let Some(id) = &p.identity {
            println!("  ID: {id}");
        }
        println!("  Scan: {}", if p.scan_capable { "yes" } else { "no" });
        println!();
    }

    if printers.len() > 1 {
        println!("Multiple devices: pass --device <ip> (or a unique part of the name/serial) to pixma scan / pixma print.");
    }

    Ok(())
}
