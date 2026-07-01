use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rusqlite::{Connection, OptionalExtension, params};
use rusqlite_migration::{M, Migrations};

use crate::{
    crypto::Crypto,
    diff::{ChangeSet, GradeChange, canonicalize, dedupe_key, diff_snapshots_with_initial},
    error::GradeError,
    portal::GradeRecord,
};

#[derive(Clone)]
pub struct Db {
    path: Arc<PathBuf>,
    crypto: Arc<Crypto>,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub name: String,
    pub email: String,
    pub uni_username: String,
    pub uni_password: String,
    pub notify_initial: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UserUpdate {
    pub name: String,
    pub email: String,
    pub enabled: bool,
    pub uni_username: Option<String>,
    pub uni_password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserSummary {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub enabled: bool,
    pub created_at: String,
    pub last_checked_at: Option<String>,
    pub last_success_at: Option<String>,
    pub consecutive_failures: u32,
    pub last_error_kind: Option<String>,
    pub last_error_at: Option<String>,
    pub row_count: usize,
}

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub hash_changed: bool,
    pub notifications: usize,
    pub hash: String,
    pub initial_notifications: bool,
}

#[derive(Debug, Clone)]
pub struct PendingNotification {
    pub id: i64,
    pub user_id: i64,
    pub user_name: String,
    pub email: String,
    pub attempts: u32,
    pub change_set: ChangeSet,
}

impl Db {
    pub fn initialize(path: impl AsRef<Path>, crypto: Arc<Crypto>) -> Result<Self, GradeError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = Connection::open(&path)?;
        configure_connection(&conn)?;
        migrations().to_latest(&mut conn)?;

        Ok(Self {
            path: Arc::new(path),
            crypto,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn health_check(&self) -> Result<(), GradeError> {
        let conn = self.connect()?;
        conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<UserSummary>, GradeError> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT u.id, u.name, u.email, u.enabled, u.created_at,
                    u.last_checked_at, u.last_success_at, u.consecutive_failures,
                    u.last_error_kind, u.last_error_at,
                    COALESCE((
                      SELECT json_array_length(s.payload)
                      FROM snapshots s
                      WHERE s.user_id = u.id
                    ), 0) AS row_count
             FROM users u
             ORDER BY u.id",
        )?;
        let rows = stmt.query_map([], user_summary_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn enabled_users(&self) -> Result<Vec<UserSummary>, GradeError> {
        Ok(self
            .list_users()?
            .into_iter()
            .filter(|user| user.enabled)
            .collect())
    }

    pub fn get_user(&self, id: i64) -> Result<Option<UserSummary>, GradeError> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT u.id, u.name, u.email, u.enabled, u.created_at,
                    u.last_checked_at, u.last_success_at, u.consecutive_failures,
                    u.last_error_kind, u.last_error_at,
                    COALESCE((
                      SELECT json_array_length(s.payload)
                      FROM snapshots s
                      WHERE s.user_id = u.id
                    ), 0) AS row_count
             FROM users u
             WHERE u.id = ?1",
            [id],
            user_summary_from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn create_user(&self, new_user: &NewUser) -> Result<i64, GradeError> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        let now = now();
        tx.execute(
            "INSERT INTO users
             (name, email, uni_username_enc, uni_password_enc, enabled, created_at, notify_initial)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
            params![
                new_user.name,
                new_user.email,
                Vec::<u8>::new(),
                Vec::<u8>::new(),
                now,
                new_user.notify_initial as i32
            ],
        )?;
        let id = tx.last_insert_rowid();
        let username_enc = self
            .crypto
            .encrypt("uni_username", id, &new_user.uni_username)?;
        let password_enc = self
            .crypto
            .encrypt("uni_password", id, &new_user.uni_password)?;
        tx.execute(
            "UPDATE users SET uni_username_enc = ?1, uni_password_enc = ?2 WHERE id = ?3",
            params![username_enc, password_enc, id],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn update_user(&self, id: i64, update: &UserUpdate) -> Result<(), GradeError> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE users SET name = ?1, email = ?2, enabled = ?3 WHERE id = ?4",
            params![update.name, update.email, update.enabled as i32, id],
        )?;
        if let Some(username) = update.uni_username.as_deref().filter(|v| !v.is_empty()) {
            let encrypted = self.crypto.encrypt("uni_username", id, username)?;
            tx.execute(
                "UPDATE users SET uni_username_enc = ?1 WHERE id = ?2",
                params![encrypted, id],
            )?;
            self.delete_session_in_tx(&tx, id)?;
        }
        if let Some(password) = update.uni_password.as_deref().filter(|v| !v.is_empty()) {
            let encrypted = self.crypto.encrypt("uni_password", id, password)?;
            tx.execute(
                "UPDATE users SET uni_password_enc = ?1 WHERE id = ?2",
                params![encrypted, id],
            )?;
            self.delete_session_in_tx(&tx, id)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_user(&self, id: i64) -> Result<(), GradeError> {
        let conn = self.connect()?;
        conn.execute("DELETE FROM users WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn credentials(&self, user_id: i64) -> Result<Credentials, GradeError> {
        let conn = self.connect()?;
        let row = conn
            .query_row(
                "SELECT uni_username_enc, uni_password_enc FROM users WHERE id = ?1",
                [user_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((username_enc, password_enc)) = row else {
            return Err(GradeError::Db(rusqlite::Error::QueryReturnedNoRows));
        };

        let username = match self.crypto.decrypt("uni_username", user_id, &username_enc) {
            Ok(value) => value,
            Err(err) => {
                self.disable_user(user_id, "decrypt")?;
                return Err(err);
            }
        };
        let password = match self.crypto.decrypt("uni_password", user_id, &password_enc) {
            Ok(value) => value,
            Err(err) => {
                self.disable_user(user_id, "decrypt")?;
                return Err(err);
            }
        };
        Ok(Credentials { username, password })
    }

    pub fn load_session_json(&self, user_id: i64) -> Result<Option<String>, GradeError> {
        let conn = self.connect()?;
        let encrypted = conn
            .query_row(
                "SELECT cookies_enc FROM sessions WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        encrypted
            .map(|blob| self.crypto.decrypt("session_cookies", user_id, &blob))
            .transpose()
    }

    pub fn save_session_json(&self, user_id: i64, cookies_json: &str) -> Result<(), GradeError> {
        let conn = self.connect()?;
        let encrypted = self
            .crypto
            .encrypt("session_cookies", user_id, cookies_json)?;
        conn.execute(
            "INSERT INTO sessions (user_id, cookies_enc, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id) DO UPDATE SET
               cookies_enc = excluded.cookies_enc,
               updated_at = excluded.updated_at",
            params![user_id, encrypted, now()],
        )?;
        Ok(())
    }

    pub fn clear_session(&self, user_id: i64) -> Result<(), GradeError> {
        let conn = self.connect()?;
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
        Ok(())
    }

    pub fn apply_successful_fetch(
        &self,
        user_id: i64,
        records: &[GradeRecord],
    ) -> Result<ApplyOutcome, GradeError> {
        let canonical = canonicalize(records)?;
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;

        let notify_initial = tx
            .query_row(
                "SELECT notify_initial FROM users WHERE id = ?1",
                [user_id],
                |row| row.get::<_, i32>(0),
            )
            .optional()?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?
            != 0;
        let old = tx
            .query_row(
                "SELECT hash, payload FROM snapshots WHERE user_id = ?1",
                [user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let (old_hash, old_payload) = old
            .as_ref()
            .map(|(hash, payload)| (Some(hash.clone()), Some(payload.as_str())))
            .unwrap_or((None, None));
        let initial_notification_requested = old.is_none() && notify_initial;
        let change_set = diff_snapshots_with_initial(
            old_hash,
            old_payload,
            &canonical,
            initial_notification_requested,
        )?;
        let initial_notifications =
            initial_notification_requested && !change_set.changes.is_empty();
        let changed = old
            .as_ref()
            .is_none_or(|(hash, _)| hash.as_str() != canonical.hash.as_str());

        if changed {
            tx.execute(
                "INSERT INTO snapshots (user_id, hash, payload, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_id) DO UPDATE SET
                   hash = excluded.hash,
                   payload = excluded.payload,
                   updated_at = excluded.updated_at",
                params![user_id, canonical.hash, canonical.payload, now()],
            )?;

            if !change_set.changes.is_empty() {
                let changes_json = serde_json::to_string(&change_set)
                    .map_err(|e| GradeError::Parse(format!("change set encode failed: {e}")))?;
                tx.execute(
                    "INSERT INTO outbox (user_id, dedupe_key, changes_json, status, created_at)
                     VALUES (?1, ?2, ?3, 'pending', ?4)
                     ON CONFLICT(dedupe_key) DO NOTHING",
                    params![
                        user_id,
                        dedupe_key(user_id, &change_set),
                        changes_json,
                        now()
                    ],
                )?;
            }
        }

        tx.execute(
            "UPDATE users
                 SET last_checked_at = ?1,
                     last_success_at = ?1,
                     consecutive_failures = 0,
                     last_error_kind = NULL,
                     last_error_at = NULL,
                     notify_initial = 0
             WHERE id = ?2",
            params![now(), user_id],
        )?;
        tx.commit()?;

        Ok(ApplyOutcome {
            hash_changed: changed,
            notifications: change_set.changes.len(),
            hash: canonical.hash,
            initial_notifications,
        })
    }

    pub fn record_failure(&self, user_id: i64, error: &GradeError) -> Result<u32, GradeError> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE users
             SET last_checked_at = ?1,
                 consecutive_failures = consecutive_failures + 1,
                 last_error_kind = ?2,
                 last_error_at = ?1
             WHERE id = ?3",
            params![now(), error.kind(), user_id],
        )?;
        let failures = conn.query_row(
            "SELECT consecutive_failures FROM users WHERE id = ?1",
            [user_id],
            |row| row.get::<_, u32>(0),
        )?;
        Ok(failures)
    }

    pub fn disable_user(&self, user_id: i64, kind: &str) -> Result<(), GradeError> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE users
             SET enabled = 0,
                 last_error_kind = ?1,
                 last_error_at = ?2
             WHERE id = ?3",
            params![kind, now(), user_id],
        )?;
        Ok(())
    }

    pub fn pending_notifications(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingNotification>, GradeError> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT o.id, o.user_id, u.name, u.email, o.attempts, o.changes_json
             FROM outbox o
             JOIN users u ON u.id = o.user_id
             WHERE o.status = 'pending'
             ORDER BY o.created_at, o.id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            let changes_json: String = row.get(5)?;
            let change_set = serde_json::from_str::<ChangeSet>(&changes_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(PendingNotification {
                id: row.get(0)?,
                user_id: row.get(1)?,
                user_name: row.get(2)?,
                email: row.get(3)?,
                attempts: row.get(4)?,
                change_set,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn mark_outbox_sent(&self, id: i64) -> Result<(), GradeError> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE outbox
             SET status = 'sent',
                 attempts = attempts + 1,
                 last_attempt_at = ?1,
                 sent_at = ?1
             WHERE id = ?2",
            params![now(), id],
        )?;
        Ok(())
    }

    pub fn mark_outbox_failed(&self, id: i64, permanent: bool) -> Result<(), GradeError> {
        let conn = self.connect()?;
        let status = if permanent { "failed" } else { "pending" };
        conn.execute(
            "UPDATE outbox
             SET status = ?1,
                 attempts = attempts + 1,
                 last_attempt_at = ?2
             WHERE id = ?3",
            params![status, now(), id],
        )?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<usize, GradeError> {
        let conn = self.connect()?;
        let count = conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE status = 'pending'",
            [],
            |row| row.get::<_, usize>(0),
        )?;
        Ok(count)
    }

    pub fn connect(&self) -> Result<Connection, GradeError> {
        let conn = Connection::open(&*self.path)?;
        configure_connection(&conn)?;
        Ok(conn)
    }

    fn delete_session_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        user_id: i64,
    ) -> Result<(), GradeError> {
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
        Ok(())
    }
}

pub fn changes_summary(changes: &[GradeChange]) -> String {
    changes
        .iter()
        .map(|change| format!("{} {}", change.kind.label(), change.nummer))
        .collect::<Vec<_>>()
        .join(", ")
}

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(include_str!("../../migrations/0001_init.sql")),
        M::up(include_str!("../../migrations/0002_notify_initial.sql")),
    ])
}

fn configure_connection(conn: &Connection) -> Result<(), GradeError> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

fn user_summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserSummary> {
    Ok(UserSummary {
        id: row.get(0)?,
        name: row.get(1)?,
        email: row.get(2)?,
        enabled: row.get::<_, i32>(3)? != 0,
        created_at: row.get(4)?,
        last_checked_at: row.get(5)?,
        last_success_at: row.get(6)?,
        consecutive_failures: row.get(7)?,
        last_error_kind: row.get(8)?,
        last_error_at: row.get(9)?,
        row_count: row.get(10)?,
    })
}

fn now() -> String {
    jiff::Timestamp::now().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::GradeRecord;
    use tempfile::tempdir;

    fn test_db() -> Db {
        let dir = tempdir().unwrap();
        let path = dir.path().join("gradewatch.db");
        let db = Db::initialize(path, Arc::new(Crypto::new([9_u8; 32]))).unwrap();
        std::mem::forget(dir);
        db
    }

    fn record(grade: &str) -> GradeRecord {
        GradeRecord {
            fields: [
                ("Nummer".to_string(), "IS-201".to_string()),
                ("Titel".to_string(), "Datenbanken".to_string()),
                ("Bewertung".to_string(), grade.to_string()),
                ("Status".to_string(), "bestanden".to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn encrypts_and_decrypts_user_credentials() {
        let db = test_db();
        let id = db
            .create_user(&NewUser {
                name: "T".into(),
                email: "t@example.test".into(),
                uni_username: "uni".into(),
                uni_password: "secret".into(),
                notify_initial: false,
            })
            .unwrap();

        let creds = db.credentials(id).unwrap();
        assert_eq!(creds.username, "uni");
        assert_eq!(creds.password, "secret");
    }

    #[test]
    fn first_snapshot_creates_no_outbox_then_update_dedupes() {
        let db = test_db();
        let id = db
            .create_user(&NewUser {
                name: "T".into(),
                email: "t@example.test".into(),
                uni_username: "uni".into(),
                uni_password: "secret".into(),
                notify_initial: false,
            })
            .unwrap();

        let first = db.apply_successful_fetch(id, &[record("2,0")]).unwrap();
        assert!(first.hash_changed);
        assert_eq!(first.notifications, 0);
        assert_eq!(db.pending_count().unwrap(), 0);

        let second = db.apply_successful_fetch(id, &[record("1,7")]).unwrap();
        assert!(second.hash_changed);
        assert_eq!(second.notifications, 1);
        assert_eq!(db.pending_count().unwrap(), 1);

        let repeated = db.apply_successful_fetch(id, &[record("1,7")]).unwrap();
        assert!(!repeated.hash_changed);
        assert_eq!(db.pending_count().unwrap(), 1);
    }

    #[test]
    fn first_snapshot_can_create_initial_outbox_when_requested() {
        let db = test_db();
        let id = db
            .create_user(&NewUser {
                name: "T".into(),
                email: "t@example.test".into(),
                uni_username: "uni".into(),
                uni_password: "secret".into(),
                notify_initial: true,
            })
            .unwrap();

        let first = db.apply_successful_fetch(id, &[record("2,0")]).unwrap();
        assert!(first.hash_changed);
        assert_eq!(first.notifications, 1);
        assert!(first.initial_notifications);

        let pending = db.pending_notifications(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].change_set.changes.len(), 1);
        assert_eq!(
            pending[0].change_set.changes[0].kind,
            crate::diff::ChangeKind::New
        );
        assert!(pending[0].change_set.changes[0].old.is_none());
        assert_eq!(
            pending[0].change_set.changes[0]
                .new
                .as_ref()
                .unwrap()
                .bewertung,
            "2,0"
        );

        let notify_initial = db
            .connect()
            .unwrap()
            .query_row(
                "SELECT notify_initial FROM users WHERE id = ?1",
                [id],
                |row| row.get::<_, i32>(0),
            )
            .unwrap();
        assert_eq!(notify_initial, 0);

        let repeated = db.apply_successful_fetch(id, &[record("2,0")]).unwrap();
        assert!(!repeated.hash_changed);
        assert_eq!(db.pending_count().unwrap(), 1);
    }

    #[test]
    fn sessions_are_encrypted_round_tripped_and_cleared() {
        let db = test_db();
        let id = db
            .create_user(&NewUser {
                name: "T".into(),
                email: "t@example.test".into(),
                uni_username: "uni".into(),
                uni_password: "secret".into(),
                notify_initial: false,
            })
            .unwrap();

        db.save_session_json(id, r#"[{"name":"JSESSIONID"}]"#)
            .unwrap();
        assert_eq!(
            db.load_session_json(id).unwrap().as_deref(),
            Some(r#"[{"name":"JSESSIONID"}]"#)
        );
        db.clear_session(id).unwrap();
        assert!(db.load_session_json(id).unwrap().is_none());
    }

    #[test]
    fn updating_credentials_clears_cached_session() {
        let db = test_db();
        let id = db
            .create_user(&NewUser {
                name: "T".into(),
                email: "t@example.test".into(),
                uni_username: "uni".into(),
                uni_password: "secret".into(),
                notify_initial: false,
            })
            .unwrap();
        db.save_session_json(id, "[]").unwrap();

        db.update_user(
            id,
            &UserUpdate {
                name: "T2".into(),
                email: "t2@example.test".into(),
                enabled: true,
                uni_username: Some("uni2".into()),
                uni_password: Some("secret2".into()),
            },
        )
        .unwrap();

        let user = db.get_user(id).unwrap().unwrap();
        let creds = db.credentials(id).unwrap();
        assert_eq!(user.name, "T2");
        assert_eq!(creds.username, "uni2");
        assert_eq!(creds.password, "secret2");
        assert!(db.load_session_json(id).unwrap().is_none());
    }

    #[test]
    fn records_failures_and_marks_outbox_sent_or_failed() {
        let db = test_db();
        let id = db
            .create_user(&NewUser {
                name: "T".into(),
                email: "t@example.test".into(),
                uni_username: "uni".into(),
                uni_password: "secret".into(),
                notify_initial: false,
            })
            .unwrap();
        assert_eq!(
            db.record_failure(id, &GradeError::Network("offline".into()))
                .unwrap(),
            1
        );
        assert_eq!(
            db.get_user(id).unwrap().unwrap().last_error_kind.unwrap(),
            "network"
        );

        db.apply_successful_fetch(id, &[record("2,0")]).unwrap();
        db.apply_successful_fetch(id, &[record("1,7")]).unwrap();
        let pending = db.pending_notifications(10).unwrap();
        assert_eq!(pending.len(), 1);
        db.mark_outbox_failed(pending[0].id, false).unwrap();
        assert_eq!(db.pending_count().unwrap(), 1);
        db.mark_outbox_sent(pending[0].id).unwrap();
        assert_eq!(db.pending_count().unwrap(), 0);
    }
}
