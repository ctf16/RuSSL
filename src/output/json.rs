use crate::scanner::ScanResult;
use anyhow::Result;

pub fn print(result: &ScanResult) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}
