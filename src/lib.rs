pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod notify;
pub mod rules;

use arboard::Clipboard;

use crate::cli::Args;
use crate::error::ClutchError;

fn list_rules(rules: &[rules::Rule]) {
    for rule in rules {
        let status = if rule.enabled { "enabled" } else { "disabled" };
        println!("[{}] {} — {}", status, rule.name, rule.pattern);
    }
}

pub fn run(args: Args) -> Result<i32, ClutchError> {
    let config_path = args.config.as_deref();
    let raw_rules = config::load_rules(config_path)?;

    if args.list_rules {
        list_rules(&raw_rules);
        return Ok(0);
    }

    let compiled = rules::compile_rules(&raw_rules)?;

    // Read clipboard
    let mut clipboard = Clipboard::new().map_err(|e| ClutchError::Clipboard(e.to_string()))?;

    const MAX_CLIPBOARD_BYTES: usize = 10 * 1024 * 1024; // 10 MB

    let text = match clipboard.get_text() {
        Ok(t) if t.is_empty() => return Err(ClutchError::EmptyClipboard),
        Ok(t) if t.len() > MAX_CLIPBOARD_BYTES => {
            return Err(ClutchError::Clipboard("clipboard content too large".into()))
        }
        Ok(t) => t,
        Err(_) => return Err(ClutchError::NonTextClipboard),
    };

    // Sanitize
    let result = engine::sanitize(&text, &compiled);

    // Output result
    notify::print_result(&result);

    if result.total_redactions == 0 {
        return Ok(2);
    }

    if args.dry_run {
        println!("\n--- dry run preview ---\n{}", result.text);
    } else {
        clipboard
            .set_text(&result.text)
            .map_err(|e| ClutchError::Clipboard(e.to_string()))?;
    }

    notify::send_notification(&result);

    Ok(0)
}
