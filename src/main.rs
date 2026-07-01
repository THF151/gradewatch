use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use gradewatch::{config::Config, crypto::Crypto, db::Db, mailer::Mailer, scheduler, web};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--gen-master-key") {
        println!("{}", Crypto::random_master_key_base64());
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|arg| arg == "--hash-password") {
        let password = args
            .get(pos + 1)
            .context("--hash-password requires the plaintext password as the next argument")?;
        println!("{}", hash_password(password)?);
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|arg| arg == "--hash-password-b64") {
        let password = args
            .get(pos + 1)
            .context("--hash-password-b64 requires the plaintext password as the next argument")?;
        use base64::{Engine, engine::general_purpose::STANDARD};
        println!("{}", STANDARD.encode(hash_password(password)?));
        return Ok(());
    }

    let config = Config::from_env()?;
    let _log_guard = init_logging(&config)?;
    prepare_data_dirs(&config)?;

    let crypto = Arc::new(Crypto::new(config.master_key));
    let db = Db::initialize(&config.database_path, crypto)?;
    let mailer = Mailer::new(config.smtp.clone());

    if args.iter().any(|arg| arg == "--healthcheck") {
        db.health_check()?;
        println!("ok");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--run-once") {
        let shutdown = Arc::new(AtomicBool::new(false));
        scheduler::run_cycle(&config, &db, &mailer, &shutdown)?;
        return Ok(());
    }

    run_service(config, db, mailer)
}

fn run_service(config: Config, db: Db, mailer: Mailer) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_shutdown = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        signal_shutdown.store(true, Ordering::Relaxed);
    })
    .context("installing signal handler")?;

    let (tx, rx) = mpsc::channel::<(&'static str, Result<(), String>)>();

    let scheduler_state = scheduler::SchedulerState::default();

    let scheduler_tx = tx.clone();
    let scheduler_shutdown = Arc::clone(&shutdown);
    let scheduler_config = config.clone();
    let scheduler_db = db.clone();
    let scheduler_mailer = mailer.clone();
    let scheduler_state_for_thread = scheduler_state.clone();
    let scheduler_handle = thread::spawn(move || {
        let result = scheduler::run_scheduler(
            scheduler_config,
            scheduler_db,
            scheduler_mailer,
            scheduler_shutdown,
            scheduler_state_for_thread,
        )
        .map_err(|e| e.to_string());
        let _ = scheduler_tx.send(("scheduler", result));
    });

    let web_tx = tx.clone();
    let web_shutdown = Arc::clone(&shutdown);
    let web_config = config.clone();
    let web_db = db.clone();
    let web_mailer = mailer.clone();
    let web_scheduler_state = scheduler_state.clone();
    let web_handle = thread::spawn(move || {
        let result = web::run_web(
            web_config,
            web_db,
            web_mailer,
            web_shutdown,
            web_scheduler_state,
        )
        .map_err(|e| e.to_string());
        let _ = web_tx.send(("web", result));
    });
    drop(tx);

    let mut first_error = None;
    if let Ok((component, result)) = rx.recv() {
        shutdown.store(true, Ordering::Relaxed);
        if let Err(err) = result {
            first_error = Some(anyhow::anyhow!("{component} stopped: {err}"));
        }
    }

    scheduler_handle
        .join()
        .map_err(|_| anyhow::anyhow!("scheduler thread panicked"))?;
    web_handle
        .join()
        .map_err(|_| anyhow::anyhow!("web thread panicked"))?;

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}

fn init_logging(config: &Config) -> Result<tracing_appender::non_blocking::WorkerGuard> {
    std::fs::create_dir_all(config.logs_dir()).context("creating logs directory")?;
    prune_logs(config)?;

    let file_appender = tracing_appender::rolling::daily(config.logs_dir(), "gradewatch.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(EnvFilter::new(&config.log_level))
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(file_writer),
        )
        .init();
    Ok(guard)
}

fn prepare_data_dirs(config: &Config) -> Result<()> {
    std::fs::create_dir_all(&config.data_dir).context("creating data directory")?;
    std::fs::create_dir_all(config.debug_dir()).context("creating debug directory")?;
    std::fs::create_dir_all(config.logs_dir()).context("creating logs directory")?;
    Ok(())
}

fn prune_logs(config: &Config) -> Result<()> {
    if config.log_retention_days == 0 {
        return Ok(());
    }
    let max_age = Duration::from_secs(config.log_retention_days as u64 * 24 * 60 * 60);
    let now = SystemTime::now();
    for entry in std::fs::read_dir(config.logs_dir()).context("reading logs directory")? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if now.duration_since(modified).unwrap_or_default() > max_age {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing password failed: {e}"))?
        .to_string())
}
