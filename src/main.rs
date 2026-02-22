use std::process;

use arboard::Clipboard;
use clap::Parser;

use clutch::cli::Args;
use clutch::config;
use clutch::engine;
use clutch::error::ClutchError;
use clutch::notify;

fn main() {
    let args = Args::parse();

    match run(args) {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("clutch: {}", e);
            process::exit(e.exit_code());
        }
    }
}

fn run(args: Args) -> Result<i32, ClutchError> {
    let config_path = args.config.as_deref();
    let rules = config::load_rules(config_path)?;

    // --list-rules: print rules and exit
    if args.list_rules {
        for rule in &rules {
            let status = if rule.enabled { "enabled" } else { "disabled" };
            println!("[{}] {} — {}", status, rule.name, rule.pattern);
        }
        return Ok(0);
    }

    // Read clipboard
    let mut clipboard = Clipboard::new().map_err(|e| ClutchError::Clipboard(e.to_string()))?;

    let text = match clipboard.get_text() {
        Ok(t) if t.is_empty() => return Err(ClutchError::EmptyClipboard),
        Ok(t) => t,
        Err(_) => return Err(ClutchError::NonTextClipboard),
    };

    // Sanitize
    let result = engine::sanitize(&text, &rules)?;

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
