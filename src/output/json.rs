use crate::error::ScanError;
use crate::scanner::ScanResult;

pub fn print(result: &ScanResult) -> Result<(), ScanError> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}
