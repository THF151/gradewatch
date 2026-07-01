use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use gradewatch::{
    config::{Config, PortalConfig, SmtpConfig, SmtpTls},
    crypto::Crypto,
    db::{Db, NewUser},
    mailer::Mailer,
    scheduler::SchedulerState,
    web,
};
use tempfile::tempdir;

#[test]
fn web_health_auth_challenge_and_dashboard_work() {
    let dir = tempdir().unwrap();
    let bind_addr = free_local_addr();
    let admin_password = "päss:wörd";
    let admin_hash = Argon2::default()
        .hash_password(admin_password.as_bytes(), &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
    let config = Config {
        master_key: [1_u8; 32],
        data_dir: dir.path().to_path_buf(),
        database_path: dir.path().join("gradewatch.db"),
        poll_interval: Duration::from_secs(60),
        poll_jitter: Duration::ZERO,
        concurrency: 1,
        http_connect_timeout: Duration::from_secs(1),
        http_read_timeout: Duration::from_secs(1),
        fetch_max_retries: 0,
        backoff_base: Duration::from_millis(1),
        backoff_cap: Duration::from_millis(1),
        failure_alert_threshold: 2,
        smtp: SmtpConfig {
            host: "exchange.uni-mannheim.de".into(),
            port: 587,
            username: None,
            password: None,
            from: None,
            tls: SmtpTls::StartTls,
        },
        alert_email: None,
        admin_user: "admin".into(),
        admin_password_hash: admin_hash,
        bind_addr,
        log_level: "error".into(),
        log_retention_days: 1,
        portal: PortalConfig {
            cas_login_url: "http://127.0.0.1/cas".into(),
            service_url: "http://127.0.0.1/service".into(),
            leistungen_url: "http://127.0.0.1/leistungen".into(),
        },
    };
    let db = Db::initialize(
        &config.database_path,
        Arc::new(Crypto::new(config.master_key)),
    )
    .unwrap();
    db.create_user(&NewUser {
        name: "Student".into(),
        email: "student@example.test".into(),
        uni_username: "uni".into(),
        uni_password: "secret".into(),
        notify_initial: false,
    })
    .unwrap();
    let mailer = Mailer::new(config.smtp.clone());
    let shutdown = Arc::new(AtomicBool::new(false));
    let web_shutdown = Arc::clone(&shutdown);
    let web_config = config.clone();
    let web_db = db.clone();
    let handle = thread::spawn(move || {
        web::run_web(
            web_config,
            web_db,
            mailer,
            web_shutdown,
            SchedulerState::default(),
        )
    });

    let base = format!("http://{bind_addr}");
    wait_for_health(&base);

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let unauthorized = agent.get(&format!("{base}/")).call().unwrap();
    assert_eq!(unauthorized.status(), 401);
    assert_eq!(
        unauthorized
            .headers()
            .get("WWW-Authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"gradewatch\", charset=\"UTF-8\"")
    );

    let auth = format!(
        "Basic {}",
        STANDARD.encode(format!("admin:{admin_password}"))
    );
    let mut response = agent
        .get(&format!("{base}/"))
        .header("Authorization", auth)
        .call()
        .unwrap();
    let body = response.body_mut().read_to_string().unwrap();
    assert!(body.contains("gradewatch"));
    assert!(body.contains("Student"));
    assert!(body.contains("Next scheduled update"));

    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap().unwrap();
}

fn free_local_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn wait_for_health(base: &str) {
    for _ in 0..20 {
        if ureq::get(&format!("{base}/health")).call().is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("web server did not start");
}
