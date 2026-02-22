use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::ClutchError;
use crate::rules::{default_rules, Rule};

#[derive(Debug, Deserialize)]
struct ConfigFile {
    rules: Vec<Rule>,
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("clutch").join("rules.toml"))
}

pub fn load_rules(config_path: Option<&Path>) -> Result<Vec<Rule>, ClutchError> {
    let mut rules = default_rules();

    let path = match config_path {
        Some(p) => {
            if !p.exists() {
                return Err(ClutchError::Config(format!(
                    "config file not found: {}",
                    p.display()
                )));
            }
            Some(p.to_path_buf())
        }
        None => default_config_path().filter(|p| p.exists()),
    };

    let Some(path) = path else {
        return Ok(rules);
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| ClutchError::Config(format!("failed to read {}: {}", path.display(), e)))?;

    let config: ConfigFile = toml::from_str(&content)
        .map_err(|e| ClutchError::Config(format!("failed to parse {}: {}", path.display(), e)))?;

    // Validate all user regex patterns upfront, even disabled ones,
    // so users get feedback immediately instead of on re-enable.
    for rule in &config.rules {
        // Skip empty-pattern check for rules that only exist to disable a default
        let is_disable_only = !rule.enabled && default_rules().iter().any(|d| d.name == rule.name);
        if rule.pattern.is_empty() && !is_disable_only {
            return Err(ClutchError::Config(format!(
                "rule '{}' is missing a pattern",
                rule.name
            )));
        }
        if !rule.pattern.is_empty() {
            regex::Regex::new(&rule.pattern).map_err(|e| ClutchError::InvalidRegex {
                name: rule.name.clone(),
                source: e,
            })?;
        }
    }

    // Merge: user rules can disable defaults or add new ones
    for user_rule in config.rules {
        if let Some(existing) = rules.iter_mut().find(|r| r.name == user_rule.name) {
            // User is overriding an existing default rule
            if !user_rule.enabled {
                existing.enabled = false;
            } else {
                existing.pattern = user_rule.pattern;
                existing.enabled = user_rule.enabled;
            }
        } else {
            // New user-defined rule
            rules.push(user_rule);
        }
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_defaults_when_no_config() {
        let rules = load_rules(None).unwrap();
        assert!(!rules.is_empty());
        assert!(rules.iter().all(|r| r.enabled));
    }

    #[test]
    fn test_user_adds_custom_rule() {
        let config = r#"
[[rules]]
name = "CUSTOM_SECRET"
pattern = "MY_SECRET_[A-Z]+"
"#;
        let file = write_temp_config(config);
        let rules = load_rules(Some(file.path())).unwrap();
        assert!(rules.iter().any(|r| r.name == "CUSTOM_SECRET"));
    }

    #[test]
    fn test_user_disables_default_rule() {
        let config = r#"
[[rules]]
name = "AWS_ACCESS_KEY"
enabled = false
"#;
        let file = write_temp_config(config);
        let rules = load_rules(Some(file.path())).unwrap();
        let aws_rule = rules.iter().find(|r| r.name == "AWS_ACCESS_KEY").unwrap();
        assert!(!aws_rule.enabled);
    }

    #[test]
    fn test_invalid_regex_returns_error() {
        let config = r#"
[[rules]]
name = "BAD_RULE"
pattern = "[invalid("
"#;
        let file = write_temp_config(config);
        let result = load_rules(Some(file.path()));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BAD_RULE"));
    }

    #[test]
    fn test_missing_explicit_config_is_error() {
        let result = load_rules(Some(Path::new("/nonexistent/path/rules.toml")));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_pattern_is_error() {
        let config = r#"
[[rules]]
name = "EMPTY_RULE"
"#;
        let file = write_temp_config(config);
        let result = load_rules(Some(file.path()));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("EMPTY_RULE"));
    }

    #[test]
    fn test_disabled_rule_with_invalid_regex_is_error() {
        let config = r#"
[[rules]]
name = "BAD_DISABLED"
pattern = "[invalid("
enabled = false
"#;
        let file = write_temp_config(config);
        let result = load_rules(Some(file.path()));
        assert!(result.is_err());
    }

    #[test]
    fn test_user_overrides_default_pattern() {
        let config = r#"
[[rules]]
name = "AWS_ACCESS_KEY"
pattern = "AKIA[0-9A-Z]{16}"
"#;
        let file = write_temp_config(config);
        let rules = load_rules(Some(file.path())).unwrap();
        let aws_rule = rules.iter().find(|r| r.name == "AWS_ACCESS_KEY").unwrap();
        assert_eq!(aws_rule.pattern, "AKIA[0-9A-Z]{16}");
        assert!(aws_rule.enabled);
    }
}
