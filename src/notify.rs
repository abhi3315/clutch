use crate::engine::SanitizeResult;

pub fn print_result(result: &SanitizeResult) {
    if result.total_redactions == 0 {
        eprintln!("clutch: clipboard is clean, nothing to redact");
    } else {
        let details: Vec<String> = result
            .matches
            .iter()
            .map(|m| format!("{}: {}", m.name, m.count))
            .collect();
        eprintln!(
            "clutch: {} secrets redacted ({})",
            result.total_redactions,
            details.join(", ")
        );
    }
}
