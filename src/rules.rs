use regex::Regex;
use serde::Deserialize;

use crate::error::ClutchError;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Rule {
    pub fn new(name: &str, pattern: &str) -> Self {
        Self {
            name: name.to_string(),
            pattern: pattern.to_string(),
            enabled: true,
        }
    }
}

#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub regex: Regex,
    pub has_named_group: bool,
}

impl CompiledRule {
    pub fn compile(rule: &Rule) -> Result<Self, ClutchError> {
        let regex = Regex::new(&rule.pattern).map_err(|e| ClutchError::InvalidRegex {
            name: rule.name.clone(),
            source: e,
        })?;
        let has_named_group = regex.capture_names().any(|n| n == Some("m"));
        Ok(Self {
            name: rule.name.clone(),
            regex,
            has_named_group,
        })
    }
}

pub fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule>, ClutchError> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .map(CompiledRule::compile)
        .collect()
}

pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule::new(
            "AWS_ACCESS_KEY",
            r"(?:^|[^A-Z0-9])(?P<m>AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)",
        ),
        Rule::new(
            "AWS_SECRET_KEY",
            r"(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*(?P<m>[A-Za-z0-9/+=]{40})",
        ),
        Rule::new(
            "GITHUB_TOKEN",
            r"(?P<m>(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{36,255})",
        ),
        Rule::new("GITHUB_PAT", r"(?P<m>github_pat_[A-Za-z0-9_]{22,255})"),
        Rule::new("STRIPE_SECRET_KEY", r"(?P<m>sk_live_[A-Za-z0-9]{24,99})"),
        Rule::new(
            "STRIPE_RESTRICTED_KEY",
            r"(?P<m>rk_live_[A-Za-z0-9]{24,99})",
        ),
        Rule::new("GOOGLE_API_KEY", r"(?P<m>AIza[0-9A-Za-z\-_]{35})"),
        Rule::new(
            "ENV_PASSWORD",
            r"(?m)^(?P<m>(?:PASSWORD|PASSWD)\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "ENV_SECRET",
            r"(?m)^(?P<m>(?:SECRET|SECRET_KEY|APP_SECRET)\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "ENV_API_KEY",
            r"(?m)^(?P<m>(?:API_KEY|APIKEY|API_SECRET)\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "ENV_TOKEN",
            r"(?m)^(?P<m>(?:TOKEN|ACCESS_TOKEN|AUTH_TOKEN)\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "DOCKER_POSTGRES_PASSWORD",
            r"(?m)^(?P<m>POSTGRES_PASSWORD\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "DOCKER_MYSQL_PASSWORD",
            r"(?m)^(?P<m>MYSQL_ROOT_PASSWORD\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "DOCKER_MONGO_PASSWORD",
            r"(?m)^(?P<m>MONGO_INITDB_ROOT_PASSWORD\s*[=:]\s*\S+)",
        ),
        Rule::new(
            "PRIVATE_KEY",
            r"(?P<m>-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        ),
        Rule::new(
            "CONNECTION_STRING",
            r"(?P<m>(?:postgresql|postgres|mongodb(?:\+srv)?|mysql)://[^\s:]+:[^\s@]+@[^\s]+)",
        ),
    ]
}
