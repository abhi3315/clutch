use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClutchError {
    #[error("clipboard error: {0}")]
    Clipboard(String),

    #[error("clipboard is empty")]
    EmptyClipboard,

    #[error("clipboard does not contain text")]
    NonTextClipboard,

    #[error("config error: {0}")]
    Config(String),

    #[error("invalid regex in rule '{name}': {source}")]
    InvalidRegex { name: String, source: regex::Error },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ClutchError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::EmptyClipboard | Self::NonTextClipboard => 2,
            _ => 1,
        }
    }
}
