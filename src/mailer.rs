use askama::Template;
use lettre::{
    Message, SmtpTransport, Transport,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::authentication::Credentials as SmtpCredentials,
};

use crate::{
    config::{SmtpConfig, SmtpTls},
    db::{Db, PendingNotification},
    diff::{ChangeSet, GradeChange},
    error::GradeError,
};

#[derive(Debug)]
pub enum MailFailure {
    Transient(String),
    Permanent(String),
}

impl MailFailure {
    fn message(&self) -> &str {
        match self {
            Self::Transient(message) | Self::Permanent(message) => message,
        }
    }

    fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

#[derive(Clone)]
pub struct Mailer {
    smtp: SmtpConfig,
}

#[derive(Debug, Clone)]
struct EmailChangeRow {
    kind: String,
    nummer: String,
    titel: String,
    old_grade: String,
    new_grade: String,
    old_status: String,
    new_status: String,
    bonus: String,
}

#[derive(Template)]
#[template(path = "email/change.html")]
struct ChangeEmailTemplate {
    user_name: String,
    rows: Vec<EmailChangeRow>,
    generated_at: String,
}

impl Mailer {
    pub fn new(smtp: SmtpConfig) -> Self {
        Self { smtp }
    }

    pub fn enabled(&self) -> bool {
        self.smtp.is_complete()
    }

    pub fn send_notification(&self, notification: &PendingNotification) -> Result<(), MailFailure> {
        let missing = self.smtp.missing_delivery_fields();
        if !missing.is_empty() {
            return Err(MailFailure::Transient(format!(
                "SMTP configuration incomplete; missing {}",
                missing.join(", ")
            )));
        }

        let subject = subject_for(&notification.change_set);
        let html = render_html(&notification.user_name, &notification.change_set)
            .map_err(|e| MailFailure::Transient(e.to_string()))?;
        let text = render_text(&notification.user_name, &notification.change_set);
        self.send(&notification.email, &subject, text, html)
    }

    pub fn send_test(&self, to: &str) -> Result<(), MailFailure> {
        let sample = ChangeSet {
            old_hash: Some("old".into()),
            new_hash: "new".into(),
            changes: vec![GradeChange {
                kind: crate::diff::ChangeKind::Updated,
                nummer: "SAMPLE-101".into(),
                titel: "Gradewatch sample".into(),
                old: Some(crate::diff::NotificationRow {
                    nummer: "SAMPLE-101".into(),
                    titel: "Gradewatch sample".into(),
                    bewertung: "2,0".into(),
                    status: "bestanden".into(),
                    bonus: String::new(),
                }),
                new: Some(crate::diff::NotificationRow {
                    nummer: "SAMPLE-101".into(),
                    titel: "Gradewatch sample".into(),
                    bewertung: "1,7".into(),
                    status: "bestanden".into(),
                    bonus: String::new(),
                }),
            }],
        };
        let notification = PendingNotification {
            id: 0,
            user_id: 0,
            user_name: "Gradewatch".into(),
            email: to.into(),
            attempts: 0,
            change_set: sample,
        };
        self.send_notification(&notification)
    }

    fn send(&self, to: &str, subject: &str, text: String, html: String) -> Result<(), MailFailure> {
        let from = self
            .smtp
            .from
            .as_deref()
            .ok_or_else(|| MailFailure::Transient("SMTP_FROM is missing".into()))?;
        let username = self
            .smtp
            .username
            .as_deref()
            .ok_or_else(|| MailFailure::Transient("SMTP_USERNAME is missing".into()))?;
        let password = self
            .smtp
            .password
            .as_deref()
            .ok_or_else(|| MailFailure::Transient("SMTP_PASSWORD is missing".into()))?;

        let from: Mailbox = from
            .parse()
            .map_err(|e| MailFailure::Permanent(format!("invalid SMTP_FROM address: {e}")))?;
        let to: Mailbox = to
            .parse()
            .map_err(|e| MailFailure::Permanent(format!("invalid recipient address: {e}")))?;

        let message = Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text))
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )
            .map_err(|e| MailFailure::Permanent(format!("could not build email: {e}")))?;

        let credentials = SmtpCredentials::new(username.to_string(), password.to_string());
        let mut builder = match self.smtp.tls {
            SmtpTls::Implicit => SmtpTransport::relay(&self.smtp.host)
                .map_err(|e| MailFailure::Transient(format!("SMTP relay setup failed: {e}")))?,
            SmtpTls::StartTls => SmtpTransport::starttls_relay(&self.smtp.host)
                .map_err(|e| MailFailure::Transient(format!("SMTP STARTTLS setup failed: {e}")))?,
        };
        builder = builder.port(self.smtp.port).credentials(credentials);
        builder.build().send(&message).map(|_| ()).map_err(|e| {
            if e.is_permanent() {
                MailFailure::Permanent(e.to_string())
            } else {
                MailFailure::Transient(e.to_string())
            }
        })
    }
}

pub fn deliver_pending(db: &Db, mailer: &Mailer, limit: usize) -> Result<usize, GradeError> {
    let pending = db.pending_notifications(limit)?;
    let mut sent = 0;
    for notification in pending {
        match mailer.send_notification(&notification) {
            Ok(()) => {
                db.mark_outbox_sent(notification.id)?;
                let initial = notification.change_set.old_hash.is_none();
                tracing::info!(
                    outbox_id = notification.id,
                    user_id = notification.user_id,
                    changes = notification.change_set.changes.len(),
                    initial,
                    "mail delivery succeeded"
                );
                if initial {
                    tracing::info!(user_id = notification.user_id, "sent initial mail to user");
                }
                sent += 1;
            }
            Err(err) => {
                tracing::warn!(
                    outbox_id = notification.id,
                    user_id = notification.user_id,
                    attempts = notification.attempts,
                    permanent = err.is_permanent(),
                    error = %err.message(),
                    "mail delivery failed"
                );
                db.mark_outbox_failed(notification.id, err.is_permanent())?;
            }
        }
    }
    Ok(sent)
}

fn subject_for(change_set: &ChangeSet) -> String {
    if change_set.changes.len() == 1 {
        let change = &change_set.changes[0];
        let grade = change
            .new
            .as_ref()
            .map(|row| row.bewertung.as_str())
            .filter(|grade| !grade.is_empty())
            .unwrap_or("updated");
        format!("Grade update: {} -> {grade}", change.titel)
    } else {
        format!("Grade updates ({})", change_set.changes.len())
    }
}

fn render_html(user_name: &str, change_set: &ChangeSet) -> Result<String, GradeError> {
    ChangeEmailTemplate {
        user_name: user_name.to_string(),
        rows: change_set.changes.iter().map(email_row).collect(),
        generated_at: jiff::Timestamp::now().to_string(),
    }
    .render()
    .map_err(|e| GradeError::Template(e.to_string()))
}

fn render_text(user_name: &str, change_set: &ChangeSet) -> String {
    let mut out = format!("Hi {user_name},\n\nGradewatch detected grade changes:\n");
    for change in &change_set.changes {
        let old_grade = change
            .old
            .as_ref()
            .map(|row| row.bewertung.as_str())
            .unwrap_or("-");
        let new_grade = change
            .new
            .as_ref()
            .map(|row| row.bewertung.as_str())
            .unwrap_or("-");
        out.push_str(&format!(
            "- {} {}: {} -> {}\n",
            change.nummer,
            change.titel,
            empty_dash(old_grade),
            empty_dash(new_grade)
        ));
    }
    out.push_str("\nThis message was generated by your self-hosted gradewatch instance.\n");
    out
}

fn email_row(change: &GradeChange) -> EmailChangeRow {
    EmailChangeRow {
        kind: change.kind.label().to_string(),
        nummer: change.nummer.clone(),
        titel: change.titel.clone(),
        old_grade: change
            .old
            .as_ref()
            .map(|row| empty_dash(&row.bewertung).to_string())
            .unwrap_or_else(|| "-".into()),
        new_grade: change
            .new
            .as_ref()
            .map(|row| empty_dash(&row.bewertung).to_string())
            .unwrap_or_else(|| "-".into()),
        old_status: change
            .old
            .as_ref()
            .map(|row| empty_dash(&row.status).to_string())
            .unwrap_or_else(|| "-".into()),
        new_status: change
            .new
            .as_ref()
            .map(|row| empty_dash(&row.status).to_string())
            .unwrap_or_else(|| "-".into()),
        bonus: change
            .new
            .as_ref()
            .or(change.old.as_ref())
            .map(|row| empty_dash(&row.bonus).to_string())
            .unwrap_or_else(|| "-".into()),
    }
}

fn empty_dash(value: &str) -> &str {
    if value.trim().is_empty() { "-" } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_stable_html() {
        let change_set = ChangeSet {
            old_hash: Some("a".into()),
            new_hash: "b".into(),
            changes: vec![GradeChange {
                kind: crate::diff::ChangeKind::Updated,
                nummer: "IS-201".into(),
                titel: "Datenbanken".into(),
                old: Some(crate::diff::NotificationRow {
                    nummer: "IS-201".into(),
                    titel: "Datenbanken".into(),
                    bewertung: "2,0".into(),
                    status: "bestanden".into(),
                    bonus: "".into(),
                }),
                new: Some(crate::diff::NotificationRow {
                    nummer: "IS-201".into(),
                    titel: "Datenbanken".into(),
                    bewertung: "1,7".into(),
                    status: "bestanden".into(),
                    bonus: "".into(),
                }),
            }],
        };

        let html = render_html("Tobias", &change_set).unwrap();
        assert!(html.contains("Tobias"));
        assert!(html.contains("Datenbanken"));
        assert!(html.contains("2,0"));
        assert!(html.contains("1,7"));
    }

    #[test]
    fn incomplete_smtp_config_reports_missing_field() {
        let mailer = Mailer::new(crate::config::SmtpConfig {
            host: "exchange.uni-mannheim.de".into(),
            port: 587,
            username: Some("uni-id".into()),
            password: Some("secret".into()),
            from: None,
            tls: crate::config::SmtpTls::StartTls,
        });

        let err = mailer.send_test("student@example.test").unwrap_err();
        assert!(matches!(err, MailFailure::Transient(_)));
        assert_eq!(
            err.message(),
            "SMTP configuration incomplete; missing SMTP_FROM"
        );
    }
}
