use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use askama::Template;
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::{
    config::Config,
    db::{Db, NewUser, UserSummary, UserUpdate},
    error::GradeError,
    mailer::{MailFailure, Mailer, deliver_pending},
    portal::fetch::PortalClient,
    scheduler::SchedulerState,
    timefmt,
};

#[derive(Clone)]
pub struct WebState {
    config: Config,
    db: Db,
    mailer: Mailer,
    scheduler_state: SchedulerState,
    auth_failures: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

#[derive(Debug, Clone)]
struct UserView {
    id: i64,
    name: String,
    email: String,
    enabled: bool,
    created_at: String,
    last_checked_at: String,
    last_success_at: String,
    consecutive_failures: u32,
    last_error_kind: String,
    last_error_at: String,
    row_count: usize,
}

#[derive(Debug, Clone, Default)]
struct UserFormView {
    id: i64,
    name: String,
    email: String,
    enabled: bool,
}

#[derive(Template)]
#[template(path = "ui/dashboard.html")]
struct DashboardTemplate {
    users: Vec<UserView>,
    pending_count: usize,
    next_scheduler_run_at: String,
    next_scheduler_run_in: String,
    last_scheduler_run_at: String,
    csrf: String,
    flash: String,
}

#[derive(Template)]
#[template(path = "ui/user_form.html")]
struct UserFormTemplate {
    title: String,
    action: String,
    submit_label: String,
    csrf: String,
    user: UserFormView,
    is_edit: bool,
}

#[derive(Template)]
#[template(path = "ui/status.html")]
struct StatusTemplate {
    title: String,
    message: String,
}

pub fn run_web(
    config: Config,
    db: Db,
    mailer: Mailer,
    shutdown: Arc<AtomicBool>,
    scheduler_state: SchedulerState,
) -> Result<(), GradeError> {
    let addr = config.bind_addr.to_string();
    let server = Server::http(&addr).map_err(|e| GradeError::Http(e.to_string()))?;
    let state = WebState {
        config,
        db,
        mailer,
        scheduler_state,
        auth_failures: Arc::new(Mutex::new(HashMap::new())),
    };
    tracing::info!(addr, "admin web UI listening");

    while !shutdown.load(Ordering::Relaxed) {
        match server.recv_timeout(Duration::from_millis(500)) {
            Ok(Some(request)) => {
                if let Err(err) = handle_request(request, &state) {
                    tracing::warn!(error = %err, "web request failed");
                }
            }
            Ok(None) => {}
            Err(err) => return Err(GradeError::Http(err.to_string())),
        }
    }
    server.unblock();
    Ok(())
}

fn handle_request(request: Request, state: &WebState) -> Result<(), GradeError> {
    let path = request.url().split('?').next().unwrap_or("/");
    if path == "/health" {
        return health(request, state);
    }

    if !authorized(&request, state) {
        return unauthorized(request);
    }

    let method = request.method().clone();
    let path = path.to_string();
    if method == Method::Get && path == "/" {
        let flash = flash_from_url(request.url());
        dashboard(request, state, flash)
    } else if method == Method::Get && path == "/users/new" {
        user_form(request, None)
    } else if method == Method::Post && path == "/users" {
        create_user(request, state)
    } else if method == Method::Post && path == "/test-mail" {
        test_mail(request, state)
    } else if method == Method::Get && path.starts_with("/users/") && path.ends_with("/edit") {
        let id = parse_user_id_with_suffix(&path, "/edit")?;
        edit_user_form(request, state, id)
    } else if method == Method::Post && path.starts_with("/users/") && path.ends_with("/delete") {
        let id = parse_user_id_with_suffix(&path, "/delete")?;
        delete_user(request, state, id)
    } else if method == Method::Post
        && path.starts_with("/users/")
        && path.ends_with("/test-connection")
    {
        let id = parse_user_id_with_suffix(&path, "/test-connection")?;
        test_connection(request, state, id)
    } else if method == Method::Post && path.starts_with("/users/") {
        let id = parse_user_id_with_suffix(&path, "")?;
        update_user(request, state, id)
    } else {
        respond_text(request, StatusCode(404), "not found")
    }
}

fn health(request: Request, state: &WebState) -> Result<(), GradeError> {
    match state.db.health_check() {
        Ok(()) => respond_text(request, StatusCode(200), "ok"),
        Err(err) => respond_text(request, StatusCode(503), &format!("unhealthy: {err}")),
    }
}

fn dashboard(request: Request, state: &WebState, flash: String) -> Result<(), GradeError> {
    let csrf = csrf_token();
    let users = state
        .db
        .list_users()?
        .into_iter()
        .map(UserView::from)
        .collect();
    let html = DashboardTemplate {
        users,
        pending_count: state.db.pending_count()?,
        next_scheduler_run_at: next_scheduler_run_at(state),
        next_scheduler_run_in: next_scheduler_run_in(state),
        last_scheduler_run_at: last_scheduler_run_at(state),
        csrf: csrf.clone(),
        flash,
    }
    .render()
    .map_err(|e| GradeError::Template(e.to_string()))?;
    respond_html_with_csrf(request, html, &csrf)
}

fn next_scheduler_run_at(state: &WebState) -> String {
    state
        .scheduler_state
        .snapshot()
        .next_run_at
        .map(timefmt::format_system_time_utc)
        .unwrap_or_else(|| "starting".into())
}

fn next_scheduler_run_in(state: &WebState) -> String {
    let snapshot = state.scheduler_state.snapshot();
    snapshot
        .next_run_at
        .map(|at| timefmt::relative_from_now(at, std::time::SystemTime::now()))
        .unwrap_or_else(|| "current cycle is running".into())
}

fn last_scheduler_run_at(state: &WebState) -> String {
    state
        .scheduler_state
        .snapshot()
        .last_finished_at
        .map(timefmt::format_system_time_utc)
        .unwrap_or_else(|| "not finished yet".into())
}

fn user_form(request: Request, user: Option<UserSummary>) -> Result<(), GradeError> {
    let csrf = csrf_token();
    let is_edit = user.is_some();
    let form_user = user.map(UserFormView::from).unwrap_or(UserFormView {
        enabled: true,
        ..UserFormView::default()
    });
    let action = if is_edit {
        format!("/users/{}", form_user.id)
    } else {
        "/users".into()
    };
    let html = UserFormTemplate {
        title: if is_edit { "Edit user" } else { "Add user" }.into(),
        action,
        submit_label: if is_edit { "Save" } else { "Add user" }.into(),
        csrf: csrf.clone(),
        user: form_user,
        is_edit,
    }
    .render()
    .map_err(|e| GradeError::Template(e.to_string()))?;
    respond_html_with_csrf(request, html, &csrf)
}

fn edit_user_form(request: Request, state: &WebState, id: i64) -> Result<(), GradeError> {
    let user = state
        .db
        .get_user(id)?
        .ok_or_else(|| GradeError::Http("user not found".into()))?;
    user_form(request, Some(user))
}

fn create_user(mut request: Request, state: &WebState) -> Result<(), GradeError> {
    let form = read_form(&mut request)?;
    require_csrf(&request, &form)?;
    let notify_initial = checkbox_checked(&form, "notify_initial");
    let id = state.db.create_user(&NewUser {
        name: required_field(&form, "name")?,
        email: required_field(&form, "email")?,
        uni_username: required_field(&form, "uni_username")?,
        uni_password: required_field(&form, "uni_password")?,
        notify_initial,
    })?;
    if notify_initial {
        return send_initial_notification_now(request, state, id);
    }
    redirect(request, "/?flash=user_added")
}

fn send_initial_notification_now(
    request: Request,
    state: &WebState,
    id: i64,
) -> Result<(), GradeError> {
    let message = match create_initial_notification(state, id) {
        Ok(message) => message,
        Err(err) => {
            tracing::warn!(
                user_id = id,
                error = %err,
                kind = err.kind(),
                "initial notification fetch failed on user create"
            );
            if matches!(err, GradeError::Auth(_)) {
                let _ = state.db.clear_session(id);
            }
            let _ = state.db.record_failure(id, &err);
            format!(
                "User added, but the initial fetch failed: {err}. The scheduler will retry on the next cycle."
            )
        }
    };
    status_page(request, "Initial notification", &message)
}

fn create_initial_notification(state: &WebState, id: i64) -> Result<String, GradeError> {
    let credentials = state.db.credentials(id)?;
    let portal = PortalClient::new(
        state.config.portal.clone(),
        state.config.http_connect_timeout,
        state.config.http_read_timeout,
    )
    .with_debug_dir(state.config.debug_dir());
    let result = portal.fetch_records(&credentials.username, &credentials.password, None)?;
    if let Some(session_json) = result.session_json.as_deref() {
        state.db.save_session_json(id, session_json)?;
    }

    let outcome = state.db.apply_successful_fetch(id, &result.records)?;
    let sent = if outcome.notifications > 0 {
        deliver_pending(&state.db, &state.mailer, 50)?
    } else {
        0
    };
    let pending = state.db.pending_count()?;
    tracing::info!(
        user_id = id,
        parsed_rows = result.records.len(),
        notifications = outcome.notifications,
        initial_notifications = outcome.initial_notifications,
        sent,
        pending,
        "initial notification processed on user create"
    );

    if outcome.initial_notifications && sent > 0 {
        Ok(format!(
            "User added. Initial grade email sent with {} new result(s).",
            outcome.notifications
        ))
    } else if outcome.initial_notifications {
        Ok(format!(
            "User added. Initial grade email queued with {} new result(s), but it has not been sent yet. Pending mails: {pending}.",
            outcome.notifications
        ))
    } else {
        Ok(format!(
            "User added. Initial fetch succeeded with {} parsed portal row(s), but no notifiable grade rows were found.",
            result.records.len()
        ))
    }
}

fn update_user(mut request: Request, state: &WebState, id: i64) -> Result<(), GradeError> {
    let form = read_form(&mut request)?;
    require_csrf(&request, &form)?;
    state.db.update_user(
        id,
        &UserUpdate {
            name: required_field(&form, "name")?,
            email: required_field(&form, "email")?,
            enabled: checkbox_checked(&form, "enabled"),
            uni_username: optional_field(&form, "uni_username"),
            uni_password: optional_field(&form, "uni_password"),
        },
    )?;
    redirect(request, "/?flash=user_saved")
}

fn delete_user(mut request: Request, state: &WebState, id: i64) -> Result<(), GradeError> {
    let form = read_form(&mut request)?;
    require_csrf(&request, &form)?;
    state.db.delete_user(id)?;
    redirect(request, "/?flash=user_deleted")
}

fn test_connection(mut request: Request, state: &WebState, id: i64) -> Result<(), GradeError> {
    let form = read_form(&mut request)?;
    require_csrf(&request, &form)?;
    let credentials = state.db.credentials(id)?;
    let session_json = state.db.load_session_json(id).ok().flatten();
    let portal = PortalClient::new(
        state.config.portal.clone(),
        state.config.http_connect_timeout,
        state.config.http_read_timeout,
    )
    .with_debug_dir(state.config.debug_dir());
    let message = match portal.fetch_records(
        &credentials.username,
        &credentials.password,
        session_json.as_deref(),
    ) {
        Ok(result) => {
            if let Some(session_json) = result.session_json.as_deref() {
                let _ = state.db.save_session_json(id, session_json);
            }
            format!("Connection OK. Parsed {} grade rows.", result.records.len())
        }
        Err(err) => format!("Connection failed: {err}"),
    };
    status_page(request, "Connection test", &message)
}

fn test_mail(mut request: Request, state: &WebState) -> Result<(), GradeError> {
    let form = read_form(&mut request)?;
    require_csrf(&request, &form)?;
    let to = required_field(&form, "email")?;
    let message = match state.mailer.send_test(&to) {
        Ok(()) => format!("Test mail sent to {to}."),
        Err(MailFailure::Permanent(err) | MailFailure::Transient(err)) => {
            format!("Test mail failed: {err}")
        }
    };
    status_page(request, "Test mail", &message)
}

fn status_page(request: Request, title: &str, message: &str) -> Result<(), GradeError> {
    let csrf = csrf_token();
    let html = StatusTemplate {
        title: title.into(),
        message: message.into(),
    }
    .render()
    .map_err(|e| GradeError::Template(e.to_string()))?;
    respond_html_with_csrf(request, html, &csrf)
}

fn authorized(request: &Request, state: &WebState) -> bool {
    let remote = request
        .remote_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    if auth_locked(&state.auth_failures, &remote) {
        return false;
    }

    let Some(header) = header(request, "Authorization") else {
        record_auth_failure(&state.auth_failures, &remote);
        return false;
    };
    let Some(encoded) = header.strip_prefix("Basic ") else {
        record_auth_failure(&state.auth_failures, &remote);
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
        record_auth_failure(&state.auth_failures, &remote);
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        record_auth_failure(&state.auth_failures, &remote);
        return false;
    };
    let Some((user, password)) = decoded.split_once(':') else {
        record_auth_failure(&state.auth_failures, &remote);
        return false;
    };

    let username_ok = state
        .config
        .admin_user
        .as_bytes()
        .ct_eq(user.as_bytes())
        .into();
    let password_ok = PasswordHash::new(&state.config.admin_password_hash)
        .ok()
        .and_then(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .ok()
        })
        .is_some();

    if username_ok && password_ok {
        clear_auth_failure(&state.auth_failures, &remote);
        true
    } else {
        record_auth_failure(&state.auth_failures, &remote);
        false
    }
}

fn auth_locked(failures: &Mutex<HashMap<String, (u32, Instant)>>, remote: &str) -> bool {
    let mut failures = failures.lock().expect("auth failure lock poisoned");
    if let Some((count, since)) = failures.get(remote).copied() {
        if since.elapsed() > Duration::from_secs(300) {
            failures.remove(remote);
            false
        } else {
            count >= 20
        }
    } else {
        false
    }
}

fn record_auth_failure(failures: &Mutex<HashMap<String, (u32, Instant)>>, remote: &str) {
    let mut failures = failures.lock().expect("auth failure lock poisoned");
    let entry = failures
        .entry(remote.to_string())
        .or_insert((0, Instant::now()));
    if entry.1.elapsed() > Duration::from_secs(300) {
        *entry = (1, Instant::now());
    } else {
        entry.0 = entry.0.saturating_add(1);
    }
}

fn clear_auth_failure(failures: &Mutex<HashMap<String, (u32, Instant)>>, remote: &str) {
    failures
        .lock()
        .expect("auth failure lock poisoned")
        .remove(remote);
}

fn require_csrf(request: &Request, form: &HashMap<String, String>) -> Result<(), GradeError> {
    let cookie = cookie(request, "gradewatch_csrf").unwrap_or_default();
    let field = form.get("csrf").cloned().unwrap_or_default();
    if !cookie.is_empty() && cookie.as_bytes().ct_eq(field.as_bytes()).into() {
        Ok(())
    } else {
        Err(GradeError::Http("invalid CSRF token".into()))
    }
}

fn read_form(request: &mut Request) -> Result<HashMap<String, String>, GradeError> {
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)?;
    Ok(url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect())
}

fn required_field(form: &HashMap<String, String>, name: &str) -> Result<String, GradeError> {
    form.get(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GradeError::Http(format!("missing form field {name}")))
}

fn optional_field(form: &HashMap<String, String>, name: &str) -> Option<String> {
    form.get(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn checkbox_checked(form: &HashMap<String, String>, name: &str) -> bool {
    form.get(name)
        .is_some_and(|value| value == "on" || value == "1")
}

fn parse_user_id_with_suffix(path: &str, suffix: &str) -> Result<i64, GradeError> {
    let trimmed = path
        .strip_prefix("/users/")
        .ok_or_else(|| GradeError::Http("invalid user route".into()))?;
    let id = if suffix.is_empty() {
        trimmed
    } else {
        trimmed
            .strip_suffix(suffix)
            .map(|s| s.trim_end_matches('/'))
            .ok_or_else(|| GradeError::Http("invalid user route".into()))?
    };
    id.parse()
        .map_err(|e| GradeError::Http(format!("invalid user id: {e}")))
}

fn flash_from_url(url: &str) -> String {
    let Some(query) = url.split_once('?').map(|(_, query)| query) else {
        return String::new();
    };
    let flash = url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "flash")
        .map(|(_, value)| value.into_owned());
    match flash.as_deref() {
        Some("user_added") => "User added.".into(),
        Some("user_saved") => "User saved.".into(),
        Some("user_deleted") => "User deleted.".into(),
        _ => String::new(),
    }
}

fn header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv(name))
        .map(|header| header.value.as_str().to_string())
}

fn cookie(request: &Request, name: &str) -> Option<String> {
    header(request, "Cookie").and_then(|raw| {
        raw.split(';').find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.to_string())
        })
    })
}

fn csrf_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn respond_html_with_csrf(request: Request, body: String, csrf: &str) -> Result<(), GradeError> {
    let response = Response::from_string(body)
        .with_status_code(StatusCode(200))
        .with_header(header_pair("Content-Type", "text/html; charset=utf-8"))
        .with_header(header_pair(
            "Set-Cookie",
            &format!("gradewatch_csrf={csrf}; HttpOnly; SameSite=Lax; Path=/"),
        ));
    request.respond(response)?;
    Ok(())
}

fn respond_text(request: Request, status: StatusCode, body: &str) -> Result<(), GradeError> {
    request.respond(
        Response::from_string(body.to_string())
            .with_status_code(status)
            .with_header(header_pair("Content-Type", "text/plain; charset=utf-8")),
    )?;
    Ok(())
}

fn redirect(request: Request, location: &str) -> Result<(), GradeError> {
    request
        .respond(Response::empty(StatusCode(303)).with_header(header_pair("Location", location)))?;
    Ok(())
}

fn unauthorized(request: Request) -> Result<(), GradeError> {
    request.respond(
        Response::from_string("authentication required")
            .with_status_code(StatusCode(401))
            .with_header(header_pair(
                "WWW-Authenticate",
                "Basic realm=\"gradewatch\", charset=\"UTF-8\"",
            )),
    )?;
    Ok(())
}

fn header_pair(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid ASCII header")
}

impl From<UserSummary> for UserView {
    fn from(user: UserSummary) -> Self {
        Self {
            id: user.id,
            name: user.name,
            email: user.email,
            enabled: user.enabled,
            created_at: user.created_at,
            last_checked_at: user.last_checked_at.unwrap_or_else(|| "-".into()),
            last_success_at: user.last_success_at.unwrap_or_else(|| "-".into()),
            consecutive_failures: user.consecutive_failures,
            last_error_kind: user.last_error_kind.unwrap_or_else(|| "-".into()),
            last_error_at: user.last_error_at.unwrap_or_else(|| "-".into()),
            row_count: user.row_count,
        }
    }
}

impl From<UserSummary> for UserFormView {
    fn from(user: UserSummary) -> Self {
        Self {
            id: user.id,
            name: user.name,
            email: user.email,
            enabled: user.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_routes() {
        assert_eq!(parse_user_id_with_suffix("/users/42", "").unwrap(), 42);
        assert_eq!(
            parse_user_id_with_suffix("/users/42/delete", "/delete").unwrap(),
            42
        );
        assert_eq!(
            parse_user_id_with_suffix("/users/42/test-connection", "/test-connection").unwrap(),
            42
        );
    }

    #[test]
    fn flash_messages_are_mapped() {
        assert_eq!(flash_from_url("/?flash=user_saved"), "User saved.");
        assert_eq!(flash_from_url("/"), "");
    }
}
