# clutch

A CLI clipboard sanitizer that redacts secrets before you paste. Built in Rust.

You copy a config snippet, run `clutch`, and your clipboard is cleaned — API keys, tokens, passwords, and private keys get replaced with labels like `[REDACTED:AWS_KEY]`. Useful when pasting into AI chats, Slack, or public channels.

## Installation

```bash
cargo install clutch
```

Or build from source:

```bash
git clone https://github.com/abhi3315/clutch.git
cd clutch
cargo install --path .
```

## Usage

```bash
# Sanitize clipboard in place
clutch

# Preview what would be redacted (doesn't modify clipboard)
clutch --dry-run

# List all active rules
clutch --list-rules

# Use a custom config file
clutch --config /path/to/rules.toml
```

## What it catches

Out of the box, clutch detects and redacts:

- AWS access key IDs and secret keys
- GitHub tokens (classic and fine-grained)
- Stripe secret and restricted keys
- Google Cloud API keys
- Generic `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=` patterns
- Docker Compose env passwords (`POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`, etc.)
- Private keys (RSA, EC, OpenSSH)
- Connection strings with embedded credentials (PostgreSQL, MongoDB, MySQL)
- Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`)
- npm tokens (`npm_`)
- PyPI tokens (`pypi-`)
- SendGrid API keys (`SG.`)
- Twilio API keys (`SK`)
- Netlify tokens (`nfp_`)
- Doppler tokens (`dp.st.`)
- JWTs (`eyJ...` base64 header.payload.signature)

## Configuration

Add custom rules or disable defaults in `~/.config/clutch/rules.toml`:

```toml
# Add a custom rule
[[rules]]
name = "SLACK_WEBHOOK"
pattern = "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"

# Disable a default rule by name
[[rules]]
name = "GOOGLE_API_KEY"
enabled = false
```

See `config/default_rules.toml` for the full format reference.

## Setting up a keyboard shortcut

### macOS

1. Open Automator → New → Quick Action
2. Set "Workflow receives" to "no input"
3. Add a "Run Shell Script" action with: `/path/to/clutch`
4. Save it (e.g., "Sanitize Clipboard")
5. Go to System Settings → Keyboard → Keyboard Shortcuts → Services
6. Assign a shortcut (e.g., `⌘⇧X`)

### Linux (GNOME)

```bash
# Settings → Keyboard → Custom Shortcuts
# Name: Sanitize Clipboard
# Command: /path/to/clutch
# Shortcut: Ctrl+Shift+X
```

### Windows (AutoHotkey)

```ahk
^+x::Run, clutch.exe
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Secrets were redacted |
| 1 | Error occurred |
| 2 | Clipboard is clean, nothing to redact |

## License

MIT
