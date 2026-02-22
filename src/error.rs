use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClutchError {
    #[error("clipboard error: {0}")]
    Clipboard(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("invalid regex in rule '{name}': {source}")]
    InvalidRegex { name: String, source: regex::Error },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
