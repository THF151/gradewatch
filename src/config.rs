use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use argon2::PasswordHash;
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::error::GradeError;

#[derive(Debug, Clone)]
pub struct Config {
    pub master_key: [u8; 32],
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub poll_interval: Duration,
    pub poll_jitter: Duration,
    pub concurrency: usize,
    pub http_connect_timeout: Duration,
    pub http_read_timeout: Duration,
    pub fetch_max_retries: usize,
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
    pub failure_alert_threshold: u32,
    pub smtp: SmtpConfig,
    pub alert_email: Option<String>,
    pub admin_user: String,
    pub admin_password_hash: String,
    pub bind_addr: SocketAddr,
    pub log_level: String,
    pub log_retention_days: u32,
    pub portal: PortalConfig,
}

#[derive(Debug, Clone)]
pub struct PortalConfig {
    pub cas_login_url: String,
    pub service_url: String,
    pub leistungen_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpTls {
    Implicit,
    StartTls,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: Option<String>,
    pub tls: SmtpTls,
}

impl SmtpConfig {
    pub fn is_complete(&self) -> bool {
        self.missing_delivery_fields().is_empty()
    }

    pub fn missing_delivery_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.username.as_deref().is_none_or(str::is_empty) {
            missing.push("SMTP_USERNAME");
        }
        if self.password.as_deref().is_none_or(str::is_empty) {
            missing.push("SMTP_PASSWORD");
        }
        if self.from.as_deref().is_none_or(str::is_empty) {
            missing.push("SMTP_FROM");
        }
        missing
    }
}

impl Config {
    pub fn from_env() -> Result<Self, GradeError> {
        let _ = dotenvy::dotenv();
        Self::from_env_without_dotenv()
    }

    pub fn from_env_without_dotenv() -> Result<Self, GradeError> {
        let data_dir = path_var("DATA_DIR", "/data");
        let database_path = env::var("DATABASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("gradewatch.db"));

        Ok(Self {
            master_key: parse_master_key(&required("MASTER_KEY")?)?,
            data_dir,
            database_path,
            poll_interval: minutes_var("POLL_INTERVAL_MINUTES", 10)?,
            poll_jitter: seconds_var("POLL_JITTER_SECONDS", 120)?,
            concurrency: usize_var("CONCURRENCY", 4)?.max(1),
            http_connect_timeout: seconds_var("HTTP_CONNECT_TIMEOUT_SECS", 5)?,
            http_read_timeout: seconds_var("HTTP_READ_TIMEOUT_SECS", 15)?,
            fetch_max_retries: usize_var("FETCH_MAX_RETRIES", 3)?,
            backoff_base: millis_var("BACKOFF_BASE_MS", 2000)?,
            backoff_cap: millis_var("BACKOFF_CAP_MS", 60000)?,
            failure_alert_threshold: u32_var("FAILURE_ALERT_THRESHOLD", 6)?,
            smtp: SmtpConfig {
                host: string_var("SMTP_HOST", "exchange.uni-mannheim.de"),
                port: u16_var("SMTP_PORT", 587)?,
                username: optional("SMTP_USERNAME"),
                password: optional("SMTP_PASSWORD"),
                from: optional("SMTP_FROM"),
                tls: match string_var("SMTP_TLS", "starttls")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "implicit" | "tls" => SmtpTls::Implicit,
                    "starttls" | "start_tls" => SmtpTls::StartTls,
                    other => {
                        return Err(GradeError::Config(format!(
                            "SMTP_TLS must be implicit or starttls, got {other}"
                        )));
                    }
                },
            },
            alert_email: optional("ALERT_EMAIL"),
            admin_user: string_var("ADMIN_USER", "admin"),
            admin_password_hash: admin_password_hash().and_then(|hash| {
                validate_admin_hash(&hash)?;
                Ok(hash)
            })?,
            bind_addr: string_var("BIND_ADDR", "0.0.0.0:8080")
                .parse()
                .map_err(|e| GradeError::Config(format!("invalid BIND_ADDR: {e}")))?,
            log_level: string_var("LOG_LEVEL", "info"),
            log_retention_days: u32_var("LOG_RETENTION_DAYS", 14)?,
            portal: PortalConfig {
                cas_login_url: string_var(
                    "PORTAL_CAS_LOGIN_URL",
                    "https://cas.uni-mannheim.de/cas/login",
                ),
                service_url: string_var(
                    "PORTAL_SERVICE_URL",
                    "https://portal2.uni-mannheim.de/portal2/rds?state=user&type=1",
                ),
                leistungen_url: string_var(
                    "PORTAL_LEISTUNGEN_URL",
                    "https://portal2.uni-mannheim.de/portal2/pages/sul/examAssessment/personExamsReadonly.xhtml?_flowId=examsOverviewForPerson-flow&navigationPosition=hisinoneMeinStudium%2CexamAssessmentForStudent&recordRequest=true",
                ),
            },
        })
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }

    pub fn debug_dir(&self) -> PathBuf {
        self.data_dir.join("debug")
    }
}

fn parse_master_key(value: &str) -> Result<[u8; 32], GradeError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|e| GradeError::Config(format!("MASTER_KEY is not valid base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| GradeError::Config("MASTER_KEY must decode to exactly 32 bytes".into()))
}

fn required(name: &str) -> Result<String, GradeError> {
    env::var(name)
        .map(|s| clean_env_value(&s))
        .map_err(|_| GradeError::Config(format!("{name} is required")))
        .and_then(|s| {
            if s.is_empty() {
                Err(GradeError::Config(format!("{name} cannot be empty")))
            } else {
                Ok(s)
            }
        })
}

fn admin_password_hash() -> Result<String, GradeError> {
    if let Some(encoded) = optional("ADMIN_PASSWORD_HASH_B64") {
        let bytes = STANDARD.decode(encoded).map_err(|e| {
            GradeError::Config(format!("ADMIN_PASSWORD_HASH_B64 is not valid base64: {e}"))
        })?;
        let hash = String::from_utf8(bytes).map_err(|e| {
            GradeError::Config(format!(
                "ADMIN_PASSWORD_HASH_B64 did not decode to UTF-8: {e}"
            ))
        })?;
        if hash.trim().is_empty() {
            return Err(GradeError::Config(
                "ADMIN_PASSWORD_HASH_B64 decoded to an empty value".into(),
            ));
        }
        Ok(hash)
    } else {
        required("ADMIN_PASSWORD_HASH")
    }
}

fn validate_admin_hash(hash: &str) -> Result<(), GradeError> {
    PasswordHash::new(hash).map(|_| ()).map_err(|e| {
        GradeError::Config(format!("ADMIN_PASSWORD_HASH is not a valid PHC hash: {e}"))
    })
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|s| clean_env_value(&s))
        .filter(|s| !s.is_empty())
}

fn path_var(name: &str, default: &str) -> PathBuf {
    env::var(name)
        .ok()
        .map(|s| clean_env_value(&s))
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(default).to_path_buf())
}

fn string_var(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .map(|s| clean_env_value(&s))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn u16_var(name: &str, default: u16) -> Result<u16, GradeError> {
    parse_var(name, default)
}

fn u32_var(name: &str, default: u32) -> Result<u32, GradeError> {
    parse_var(name, default)
}

fn usize_var(name: &str, default: usize) -> Result<usize, GradeError> {
    parse_var(name, default)
}

fn seconds_var(name: &str, default: u64) -> Result<Duration, GradeError> {
    Ok(Duration::from_secs(parse_var(name, default)?))
}

fn minutes_var(name: &str, default: u64) -> Result<Duration, GradeError> {
    Ok(Duration::from_secs(parse_var::<u64>(name, default)? * 60))
}

fn millis_var(name: &str, default: u64) -> Result<Duration, GradeError> {
    Ok(Duration::from_millis(parse_var(name, default)?))
}

fn parse_var<T>(name: &str, default: T) -> Result<T, GradeError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => clean_env_value(&raw)
            .parse()
            .map_err(|e| GradeError::Config(format!("invalid {name}: {e}"))),
        _ => Ok(default),
    }
}

fn clean_env_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if (bytes[0] == b'"' && bytes[trimmed.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[trimmed.len() - 1] == b'\'')
        {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_master_key() {
        let key = parse_master_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(key, [0_u8; 32]);
    }

    #[test]
    fn rejects_wrong_sized_master_key() {
        assert!(parse_master_key("AAAA").is_err());
    }

    #[test]
    fn strips_matching_env_quotes() {
        assert_eq!(clean_env_value(r#""abc""#), "abc");
        assert_eq!(clean_env_value("'abc'"), "abc");
        assert_eq!(clean_env_value("abc"), "abc");
    }

    #[test]
    fn validates_admin_hash_shape() {
        assert!(validate_admin_hash("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$7w8aC9+oCw1+zfl+t2KJwAfWT8v12bJeLKA3Heg96iQ").is_ok());
        assert!(validate_admin_hash("not-a-phc-hash").is_err());
    }

    #[test]
    fn reports_exact_missing_smtp_delivery_fields() {
        let config = SmtpConfig {
            host: "exchange.uni-mannheim.de".into(),
            port: 587,
            username: Some("uni-id".into()),
            password: Some("secret".into()),
            from: None,
            tls: SmtpTls::StartTls,
        };

        assert!(!config.is_complete());
        assert_eq!(config.missing_delivery_fields(), vec!["SMTP_FROM"]);
    }
}
