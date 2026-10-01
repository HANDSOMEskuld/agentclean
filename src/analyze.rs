use crate::model::ScanReport;
pub fn summarize(r: &ScanReport) -> String {
    format!(
        "{} files, {} bytes, {} errors",
        r.scanned_files,
        r.scanned_bytes,
        r.errors.len()
    )
}
