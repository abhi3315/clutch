use std::process;

use arboard::Clipboard;
use clap::Parser;

use clutch::cli::Args;
use clutch::config;
use clutch::engine;
use clutch::notify;

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("clutch: {}", e);
        process::exit(1);
    }
}

fn run(args: Args) -> Result<(), clutch::error::ClutchError> {
    let config_path = args.config.as_deref();
    let rules = config::load_rules(config_path)?;

    // --list-rules: print rules and exit
    if args.list_rules {
        for rule in &rules {
            let status = if rule.enabled { "enabled" } else { "disabled" };
            println!("[{}] {} — {}", status, rule.name, rule.pattern);
        }
        return Ok(());
    }

    // Read clipboard
    let mut clipboard =
        Clipboard::new().map_err(|e| clutch::error::ClutchError::Clipboard(e.to_string()))?;

    let text = match clipboard.get_text() {
        Ok(t) if t.is_empty() => {
            eprintln!("clutch: clipboard is empty");
            process::exit(2);
        }
        Ok(t) => t,
        Err(_) => {
            eprintln!("clutch: clipboard does not contain text");
            process::exit(2);
        }
    };

    // Sanitize
    let result = engine::sanitize(&text, &rules)?;

    // Output result
    notify::print_result(&result);

    if result.total_redactions == 0 {
        process::exit(2);
    }

    if args.dry_run {
        println!("\n--- dry run preview ---\n{}", result.text);
    } else {
        clipboard
            .set_text(&result.text)
            .map_err(|e| clutch::error::ClutchError::Clipboard(e.to_string()))?;
    }

    notify::send_notification(&result);

    Ok(())
}
