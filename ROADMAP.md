# Clutch roadmap

## High priority

### stdin/stdout support
Read from stdin instead of clipboard when input is piped. Makes clutch composable with other tools and useful in scripts.
```bash
echo "PASSWORD=hunter2" | clutch
clutch < .env > .env.clean
cat config.yml | clutch --dry-run
```
Clipboard mode stays the default when no stdin is detected.

### `--init` command
Generate a starter `~/.config/clutch/rules.toml` with comments and examples. Saves users from digging through the repo for the example config.
```bash
clutch --init
```

### ~~More default rules~~ ✅
Added in v0.1: Slack tokens, npm tokens, PyPI tokens, SendGrid keys, Twilio API keys, Netlify tokens, Doppler tokens, JWTs. Still open: Vercel tokens, base64-encoded secrets in Kubernetes YAML.

### Shell completions
Auto-generate completions for bash, zsh, and fish using clap's built-in support.
```bash
clutch --completions zsh >> ~/.zfunc/_clutch
```

## Medium priority

### `--undo`
Save the original clipboard contents to a temp file before overwriting. Let users restore with `clutch --undo` if they redacted by mistake.

### Custom redaction format
A `--format` flag to control what the redacted text looks like.
```bash
clutch --format '***'
clutch --format '<REMOVED:{name}>'
clutch --format '[REDACTED:{name}]'  # current default
```

### JSON output
Machine-readable output for editor plugins or GUI wrappers.
```bash
clutch --json
```
```json
{
  "redactions": 3,
  "rules_matched": [
    {"name": "AWS_KEY", "count": 1},
    {"name": "PASSWORD", "count": 2}
  ],
  "sanitized_text": "..."
}
```

## Not planned

- **Daemon/watch mode** — clutch is designed to run once and exit. A persistent process watching the clipboard is a different tool with different tradeoffs (battery, permissions, security).
- **GUI** — out of scope. Clutch is a CLI tool. A GUI wrapper could be built separately using the library.
- **Clipboard history** — OS-level concern. macOS and most Linux clipboard managers already handle this.
- **Remote rule updates** — fetching rules from a URL adds a network dependency and a security risk. Users can manage their own config files.
