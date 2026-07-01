use thiserror::Error;

#[derive(Debug, Error)]
pub enum GradeError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("decrypt error: {0}")]
    Decrypt(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("mail error: {0}")]
    Mail(String),
    #[error("template error: {0}")]
    Template(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http error: {0}")]
    Http(String),
}

impl GradeError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Network(_) => "network",
            Self::Auth(_) => "auth",
            Self::Parse(_) => "parse",
            Self::Decrypt(_) => "decrypt",
            Self::Crypto(_) => "crypto",
            Self::Db(_) => "db",
            Self::Migration(_) => "db",
            Self::Mail(_) => "mail",
            Self::Template(_) => "template",
            Self::Io(_) => "io",
            Self::Http(_) => "http",
        }
    }
}

impl From<ureq::Error> for GradeError {
    fn from(value: ureq::Error) -> Self {
        match value {
            ureq::Error::StatusCode(code) => Self::Http(format!("HTTP status {code}")),
            other => Self::Network(other.to_string()),
        }
    }
}
