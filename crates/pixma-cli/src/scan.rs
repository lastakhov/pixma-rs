use std::path::PathBuf;

use anyhow::{bail, Result};
use pixma_protocol::scanner::commands::{ColorMode, ScanParams};
use pixma_protocol::scanner::image::{OutputFormat, save_scan};
use pixma_protocol::scanner::session;

use crate::device;

pub async fn run(
    output: PathBuf,
    resolution: u16,
    color: String,
    format: Option<String>,
    device: Option<String>,
) -> Result<()> {
    let printer = device::resolve(device.as_deref(), true).await?;
    let ip = printer.ip;

    let color_mode = match color.as_str() {
        "grayscale" | "gray" => ColorMode::Grayscale,
        _ => ColorMode::Color,
    };

    let params = ScanParams::a4(resolution, color_mode);

    let out_format = match format.as_deref() {
        Some("jpeg" | "jpg") => OutputFormat::Jpeg,
        Some("png") => OutputFormat::Png,
        None => OutputFormat::from_extension(&output),
        Some(other) => bail!("Unsupported format: {other}"),
    };

    eprintln!("Scanning at {} DPI ({:?}) via CHMP...", resolution, color_mode);
    let result = session::scan(ip, &params).await?;
    eprintln!(
        "Received {} bytes ({} x {} pixels)",
        result.data.len(),
        result.width,
        result.height
    );

    save_scan(&result, &output, out_format)?;
    eprintln!("Saved to {}", output.display());

    Ok(())
}
