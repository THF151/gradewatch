use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime},
};

use rand::Rng;

use crate::{
    config::Config,
    db::{Db, UserSummary},
    error::GradeError,
    mailer::{Mailer, deliver_pending},
    portal::fetch::PortalClient,
    timefmt,
};

#[derive(Debug, Clone, Default)]
pub struct SchedulerState {
    inner: Arc<RwLock<SchedulerSnapshot>>,
    sync_requested: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchedulerPhase {
    #[default]
    Starting,
    Running,
    Waiting,
    SyncQueued,
}

#[derive(Debug, Clone, Default)]
pub struct SchedulerSnapshot {
    pub next_run_at: Option<SystemTime>,
    pub last_started_at: Option<SystemTime>,
    pub last_finished_at: Option<SystemTime>,
    pub sync_requested: bool,
    pub phase: SchedulerPhase,
}

impl SchedulerState {
    pub fn snapshot(&self) -> SchedulerSnapshot {
        let mut snapshot = self
            .inner
            .read()
            .expect("scheduler state lock poisoned")
            .clone();
        snapshot.sync_requested = self.sync_requested();
        if snapshot.sync_requested {
            snapshot.phase = SchedulerPhase::SyncQueued;
        }
        snapshot
    }

    pub fn request_sync_now(&self) {
        self.sync_requested.store(true, Ordering::SeqCst);
        let mut state = self.inner.write().expect("scheduler state lock poisoned");
        state.phase = SchedulerPhase::SyncQueued;
        state.next_run_at = Some(SystemTime::now());
    }

    fn mark_started(&self, at: SystemTime) {
        let mut state = self.inner.write().expect("scheduler state lock poisoned");
        state.phase = SchedulerPhase::Running;
        state.last_started_at = Some(at);
        state.next_run_at = None;
    }

    fn mark_finished(&self, at: SystemTime) {
        self.inner
            .write()
            .expect("scheduler state lock poisoned")
            .last_finished_at = Some(at);
    }

    fn mark_waiting(&self, at: SystemTime) {
        let mut state = self.inner.write().expect("scheduler state lock poisoned");
        state.phase = SchedulerPhase::Waiting;
        state.next_run_at = Some(at);
    }

    fn sync_requested(&self) -> bool {
        self.sync_requested.load(Ordering::SeqCst)
    }

    fn take_sync_request(&self) -> bool {
        self.sync_requested.swap(false, Ordering::SeqCst)
    }
}

pub fn run_scheduler(
    config: Config,
    db: Db,
    mailer: Mailer,
    shutdown: Arc<AtomicBool>,
    state: SchedulerState,
) -> Result<(), GradeError> {
    let mut next_run_at = SystemTime::now();
    while !shutdown.load(Ordering::Relaxed) {
        if state.take_sync_request() {
            next_run_at = SystemTime::now();
            tracing::info!("manual scheduler sync requested; starting cycle now");
        }

        let started_at = SystemTime::now();
        tracing::info!(
            scheduled_for = %timefmt::format_system_time_utc(next_run_at),
            started_at = %timefmt::format_system_time_utc(started_at),
            overdue_by_seconds = overdue_by_seconds(next_run_at, started_at),
            "scheduler cycle deadline reached; starting cycle"
        );
        state.mark_started(started_at);
        run_cycle(&config, &db, &mailer, &shutdown)?;
        let finished_at = SystemTime::now();
        state.mark_finished(finished_at);

        if state.take_sync_request() {
            next_run_at = SystemTime::now();
            tracing::info!(
                "manual scheduler sync was queued during cycle; starting another cycle now"
            );
            continue;
        }

        next_run_at = next_deadline_after(next_run_at, config.poll_interval, finished_at);
        let delay = delay_until(next_run_at, SystemTime::now());
        state.mark_waiting(next_run_at);
        tracing::info!(
            next_run_at = %timefmt::format_system_time_utc(next_run_at),
            in_seconds = delay.as_secs(),
            "next scheduler cycle scheduled"
        );
        sleep_until(next_run_at, &shutdown, &state);
    }
    Ok(())
}

pub fn run_cycle(
    config: &Config,
    db: &Db,
    mailer: &Mailer,
    shutdown: &Arc<AtomicBool>,
) -> Result<(), GradeError> {
    let users = db.enabled_users()?;
    tracing::info!(users = users.len(), "scheduler cycle started");

    let portal = PortalClient::new(
        config.portal.clone(),
        config.http_connect_timeout,
        config.http_read_timeout,
    )
    .with_debug_dir(config.debug_dir());

    for chunk in users.chunks(config.concurrency) {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let handles = chunk
            .iter()
            .cloned()
            .map(|user| {
                let db = db.clone();
                let config = config.clone();
                let portal = portal.clone();
                let shutdown = Arc::clone(shutdown);
                thread::spawn(move || {
                    catch_unwind(AssertUnwindSafe(|| {
                        process_user(&config, &db, &portal, &user, &shutdown)
                    }))
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            match handle.join() {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(err))) => {
                    tracing::warn!(error = %err, kind = err.kind(), "user processing failed");
                }
                Ok(Err(_panic)) => {
                    tracing::error!("user worker panicked");
                }
                Err(_panic) => {
                    tracing::error!("worker thread panicked");
                }
            }
        }
    }

    let sent = deliver_pending(db, mailer, 50)?;
    tracing::info!(
        sent,
        pending = db.pending_count()?,
        "scheduler cycle finished"
    );
    Ok(())
}

fn process_user(
    config: &Config,
    db: &Db,
    portal: &PortalClient,
    user: &UserSummary,
    shutdown: &Arc<AtomicBool>,
) -> Result<(), GradeError> {
    jitter_sleep(config.poll_jitter, shutdown);
    if shutdown.load(Ordering::Relaxed) {
        return Ok(());
    }

    let credentials = match db.credentials(user.id) {
        Ok(credentials) => credentials,
        Err(err) if is_missing_user(&err) => {
            tracing::info!(
                user_id = user.id,
                "user disappeared before scheduler processing"
            );
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    let session_json = db.load_session_json(user.id).ok().flatten();
    let result = fetch_with_retries(
        config,
        || {
            portal.fetch_records(
                &credentials.username,
                &credentials.password,
                session_json.as_deref(),
            )
        },
        shutdown,
    );

    match result {
        Ok(result) => {
            if let Some(session_json) = result.session_json.as_deref() {
                db.save_session_json(user.id, session_json)?;
            }
            let outcome = match db.apply_successful_fetch(user.id, &result.records) {
                Ok(outcome) => outcome,
                Err(err) if is_missing_user(&err) => {
                    tracing::info!(
                        user_id = user.id,
                        "user disappeared before fetch result could be stored"
                    );
                    return Ok(());
                }
                Err(err) => return Err(err),
            };
            tracing::info!(
                user_id = user.id,
                hash_changed = outcome.hash_changed,
                notifications = outcome.notifications,
                initial_notifications = outcome.initial_notifications,
                hash = %outcome.hash,
                rows = result.records.len(),
                "user fetch succeeded"
            );
            Ok(())
        }
        Err(err) => {
            tracing::warn!(
                user_id = user.id,
                error = %err,
                kind = err.kind(),
                "user fetch failed"
            );
            if matches!(err, GradeError::Auth(_)) {
                let _ = db.clear_session(user.id);
            }
            let failures = match db.record_failure(user.id, &err) {
                Ok(failures) => failures,
                Err(record_err) => {
                    tracing::warn!(
                        user_id = user.id,
                        fetch_error = %err,
                        record_error = %record_err,
                        "could not record user fetch failure"
                    );
                    return Err(err);
                }
            };
            if matches!(err, GradeError::Auth(_)) && failures >= config.failure_alert_threshold {
                db.disable_user(user.id, "auth")?;
            }
            Err(err)
        }
    }
}

fn fetch_with_retries<F, T>(
    config: &Config,
    mut fetch: F,
    shutdown: &Arc<AtomicBool>,
) -> Result<T, GradeError>
where
    F: FnMut() -> Result<T, GradeError>,
{
    let mut attempt = 0;
    loop {
        match fetch() {
            Ok(value) => return Ok(value),
            Err(err) if is_transient(&err) && attempt < config.fetch_max_retries => {
                attempt += 1;
                let sleep = retry_delay(config.backoff_base, config.backoff_cap, attempt);
                tracing::warn!(
                    attempt,
                    delay_ms = sleep.as_millis(),
                    error = %err,
                    "transient fetch failed; retrying"
                );
                sleep_for(sleep, shutdown);
            }
            Err(err) => return Err(err),
        }
    }
}

fn is_transient(err: &GradeError) -> bool {
    matches!(err, GradeError::Network(_) | GradeError::Http(_))
}

fn is_missing_user(err: &GradeError) -> bool {
    matches!(err, GradeError::Db(rusqlite::Error::QueryReturnedNoRows))
}

fn retry_delay(base: Duration, cap: Duration, attempt: usize) -> Duration {
    let factor = 1_u32
        .checked_shl(attempt.saturating_sub(1) as u32)
        .unwrap_or(u32::MAX);
    let delay = base.saturating_mul(factor);
    delay.min(cap)
}

fn jitter_sleep(max: Duration, shutdown: &Arc<AtomicBool>) {
    if max.is_zero() {
        return;
    }
    let jitter_ms = rand::thread_rng().gen_range(0..=max.as_millis() as u64);
    sleep_for(Duration::from_millis(jitter_ms), shutdown);
}

fn next_deadline_after(
    previous_deadline: SystemTime,
    interval: Duration,
    now: SystemTime,
) -> SystemTime {
    if interval.is_zero() {
        return now;
    }

    let mut deadline = previous_deadline;
    loop {
        deadline = deadline.checked_add(interval).unwrap_or(now);
        if deadline_after(deadline, now) {
            return deadline;
        }
    }
}

fn deadline_after(deadline: SystemTime, now: SystemTime) -> bool {
    deadline
        .duration_since(now)
        .map(|remaining| !remaining.is_zero())
        .unwrap_or(false)
}

fn deadline_due(deadline: SystemTime, now: SystemTime) -> bool {
    !deadline_after(deadline, now)
}

fn delay_until(deadline: SystemTime, now: SystemTime) -> Duration {
    deadline.duration_since(now).unwrap_or(Duration::ZERO)
}

fn overdue_by_seconds(deadline: SystemTime, now: SystemTime) -> u64 {
    now.duration_since(deadline)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn sleep_until(deadline: SystemTime, shutdown: &Arc<AtomicBool>, state: &SchedulerState) {
    loop {
        if shutdown.load(Ordering::Relaxed) || state.sync_requested() {
            return;
        }
        let now = SystemTime::now();
        if deadline_due(deadline, now) {
            return;
        }
        sleep_until_interruptible(
            delay_until(deadline, now).min(Duration::from_secs(1)),
            shutdown,
            state,
        );
    }
}

fn sleep_until_interruptible(
    duration: Duration,
    shutdown: &Arc<AtomicBool>,
    state: &SchedulerState,
) {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline
        && !shutdown.load(Ordering::Relaxed)
        && !state.sync_requested()
    {
        thread::sleep((deadline - std::time::Instant::now()).min(Duration::from_millis(250)));
    }
}

fn sleep_for(duration: Duration, shutdown: &Arc<AtomicBool>) {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline && !shutdown.load(Ordering::Relaxed) {
        thread::sleep((deadline - std::time::Instant::now()).min(Duration::from_millis(250)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        thread,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    fn at_seconds(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn retry_delay_caps() {
        assert_eq!(
            retry_delay(Duration::from_secs(2), Duration::from_secs(60), 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            retry_delay(Duration::from_secs(2), Duration::from_secs(60), 3),
            Duration::from_secs(8)
        );
        assert_eq!(
            retry_delay(Duration::from_secs(30), Duration::from_secs(60), 4),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn manual_sync_request_wakes_scheduler_sleep() {
        let state = SchedulerState::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        state.request_sync_now();

        sleep_until(
            SystemTime::now() + Duration::from_secs(60),
            &shutdown,
            &state,
        );
        assert!(state.sync_requested());
        assert!(state.take_sync_request());
        assert!(!state.sync_requested());
    }

    #[test]
    fn next_deadline_preserves_normal_cadence() {
        let previous_due = at_seconds(10 * 60 * 60);
        let now = previous_due + Duration::from_secs(5);

        assert_eq!(
            next_deadline_after(previous_due, Duration::from_secs(60 * 60), now),
            at_seconds(11 * 60 * 60)
        );
    }

    #[test]
    fn next_deadline_skips_missed_intervals_after_slow_cycle() {
        let previous_due = at_seconds(10 * 60 * 60);
        let now = at_seconds(12 * 60 * 60 + 30 * 60);

        assert_eq!(
            next_deadline_after(previous_due, Duration::from_secs(60 * 60), now),
            at_seconds(13 * 60 * 60)
        );
    }

    #[test]
    fn next_deadline_handles_laptop_sleep_resume_case() {
        let previous_due = at_seconds(16 * 60 * 60 + 55 * 60);
        let resumed_at = at_seconds(18 * 60 * 60 + 25 * 60);

        assert_eq!(
            next_deadline_after(previous_due, Duration::from_secs(60 * 60), resumed_at),
            at_seconds(18 * 60 * 60 + 55 * 60)
        );
    }

    #[test]
    fn next_deadline_advances_on_exact_boundary() {
        let previous_due = at_seconds(10 * 60 * 60);
        let now = at_seconds(11 * 60 * 60);

        assert_eq!(
            next_deadline_after(previous_due, Duration::from_secs(60 * 60), now),
            at_seconds(12 * 60 * 60)
        );
    }

    #[test]
    fn past_wall_clock_deadline_returns_immediately() {
        let state = SchedulerState::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let started = Instant::now();

        sleep_until(UNIX_EPOCH, &shutdown, &state);

        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn future_wall_clock_deadline_waits_until_due() {
        let state = SchedulerState::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let started = Instant::now();

        sleep_until(
            SystemTime::now() + Duration::from_millis(25),
            &shutdown,
            &state,
        );

        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn sync_request_wakes_future_wall_clock_deadline() {
        let state = SchedulerState::default();
        let sleep_state = state.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sleep_shutdown = Arc::clone(&shutdown);
        let started = Instant::now();

        let handle = thread::spawn(move || {
            sleep_until(
                SystemTime::now() + Duration::from_secs(60),
                &sleep_shutdown,
                &sleep_state,
            );
        });
        thread::sleep(Duration::from_millis(20));
        state.request_sync_now();
        handle.join().unwrap();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(state.sync_requested());
    }

    #[test]
    fn classifies_only_transport_errors_as_transient() {
        assert!(is_transient(&GradeError::Network("dns".into())));
        assert!(is_transient(&GradeError::Http("502".into())));
        assert!(!is_transient(&GradeError::Auth("bad".into())));
        assert!(!is_transient(&GradeError::Parse("html".into())));
    }
}
