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

#[cfg(target_os = "macos")]
pub fn send_notification(result: &SanitizeResult) {
    let message = if result.total_redactions == 0 {
        "Clipboard is clean".to_string()
    } else {
        format!("{} secrets redacted", result.total_redactions)
    };

    // Escape quotes and backslashes to prevent AppleScript injection
    let escaped = message
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    let script = format!(r#"display notification "{}" with title "Clutch""#, escaped);

    // Best-effort — don't fail the whole program if notification fails
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output();
}

#[cfg(not(target_os = "macos"))]
pub fn send_notification(_result: &SanitizeResult) {
    // No-op on non-macOS platforms
}
