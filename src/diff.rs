use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::GradeError, portal::GradeRecord};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRow {
    pub key: String,
    pub nummer: String,
    pub titel: String,
    pub bewertung: String,
    pub status: String,
    pub bonus: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRow {
    pub nummer: String,
    pub titel: String,
    pub bewertung: String,
    pub status: String,
    pub bonus: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    New,
    Updated,
    Removed,
}

impl ChangeKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::New => "New result",
            Self::Updated => "Updated result",
            Self::Removed => "Removed result",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradeChange {
    pub kind: ChangeKind,
    pub nummer: String,
    pub titel: String,
    pub old: Option<NotificationRow>,
    pub new: Option<NotificationRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub old_hash: Option<String>,
    pub new_hash: String,
    pub changes: Vec<GradeChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSnapshot {
    pub hash: String,
    pub payload: String,
    pub rows: Vec<SnapshotRow>,
}

pub fn canonicalize(records: &[GradeRecord]) -> Result<CanonicalSnapshot, GradeError> {
    let mut rows = records
        .iter()
        .filter(|record| !is_account_record(record))
        .enumerate()
        .map(|(idx, record)| {
            let nummer = clean(record.get("Nummer"));
            let key = if nummer.is_empty() {
                format!("structural:{idx:05}:{}", clean(record.get("Titel")))
            } else {
                format!("nummer:{nummer}")
            };
            SnapshotRow {
                key,
                nummer,
                titel: clean(record.get("Titel")),
                bewertung: clean(record.get("Bewertung")),
                status: clean(record.get("Status")),
                bonus: clean(record.get("Bonus")),
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    let payload = serde_json::to_string(&rows)
        .map_err(|e| GradeError::Parse(format!("canonical snapshot serialize failed: {e}")))?;
    let hash = hex_sha256(payload.as_bytes());
    Ok(CanonicalSnapshot {
        hash,
        payload,
        rows,
    })
}

pub fn diff_snapshots(
    old_hash: Option<String>,
    old_payload: Option<&str>,
    new: &CanonicalSnapshot,
) -> Result<ChangeSet, GradeError> {
    diff_snapshots_with_initial(old_hash, old_payload, new, false)
}

pub fn diff_snapshots_with_initial(
    old_hash: Option<String>,
    old_payload: Option<&str>,
    new: &CanonicalSnapshot,
    notify_initial: bool,
) -> Result<ChangeSet, GradeError> {
    if old_hash.as_deref() == Some(new.hash.as_str()) {
        return Ok(ChangeSet {
            old_hash,
            new_hash: new.hash.clone(),
            changes: Vec::new(),
        });
    }

    let old_rows = match old_payload {
        Some(payload) => serde_json::from_str::<Vec<SnapshotRow>>(payload)
            .map_err(|e| GradeError::Parse(format!("stored snapshot decode failed: {e}")))?,
        None => Vec::new(),
    }
    .into_iter()
    .filter(|row| !is_account_snapshot_row(row))
    .collect::<Vec<_>>();

    let old_by_nummer = old_rows
        .iter()
        .filter(|row| !row.nummer.is_empty())
        .map(|row| (row.nummer.clone(), row.clone()))
        .collect::<BTreeMap<_, _>>();
    let new_by_nummer = new
        .rows
        .iter()
        .filter(|row| !row.nummer.is_empty())
        .map(|row| (row.nummer.clone(), row.clone()))
        .collect::<BTreeMap<_, _>>();

    let all_keys = old_by_nummer
        .keys()
        .chain(new_by_nummer.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();

    for nummer in all_keys {
        match (old_by_nummer.get(&nummer), new_by_nummer.get(&nummer)) {
            (None, Some(new_row)) if old_payload.is_some() || notify_initial => {
                changes.push(GradeChange {
                    kind: ChangeKind::New,
                    nummer,
                    titel: new_row.titel.clone(),
                    old: None,
                    new: Some(new_row.clone().into()),
                })
            }
            (Some(old_row), Some(new_row))
                if old_row.bewertung != new_row.bewertung
                    || old_row.status != new_row.status
                    || old_row.bonus != new_row.bonus =>
            {
                changes.push(GradeChange {
                    kind: ChangeKind::Updated,
                    nummer,
                    titel: new_row.titel.clone(),
                    old: Some(old_row.clone().into()),
                    new: Some(new_row.clone().into()),
                });
            }
            (Some(old_row), None) => changes.push(GradeChange {
                kind: ChangeKind::Removed,
                nummer,
                titel: old_row.titel.clone(),
                old: Some(old_row.clone().into()),
                new: None,
            }),
            _ => {}
        }
    }

    Ok(ChangeSet {
        old_hash,
        new_hash: new.hash.clone(),
        changes,
    })
}

pub fn dedupe_key(user_id: i64, change_set: &ChangeSet) -> String {
    hex_sha256(
        format!(
            "{user_id}:{}:{}",
            change_set.old_hash.as_deref().unwrap_or("none"),
            change_set.new_hash
        )
        .as_bytes(),
    )
}

pub fn hex_sha256(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn clean(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_account_record(record: &GradeRecord) -> bool {
    let kind = record.get("_row_kind").to_ascii_lowercase();
    if kind.contains("konto") || kind.contains("prüfungsordnung") {
        return true;
    }

    is_account_title(record.get("Titel"))
}

fn is_account_snapshot_row(row: &SnapshotRow) -> bool {
    is_account_title(&row.titel)
}

fn is_account_title(title: &str) -> bool {
    let title = title.to_ascii_lowercase();
    title.contains("vorläufige durchschnittsnote") || title.contains("erworbene ects")
}

impl From<SnapshotRow> for NotificationRow {
    fn from(value: SnapshotRow) -> Self {
        Self {
            nummer: value.nummer,
            titel: value.titel,
            bewertung: value.bewertung,
            status: value.status,
            bonus: value.bonus,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(fields: &[(&str, &str)]) -> GradeRecord {
        GradeRecord {
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn hash_is_stable_independent_of_input_order() {
        let a = canonicalize(&[
            rec(&[("Nummer", "B"), ("Titel", "B"), ("Bewertung", "2,0")]),
            rec(&[("Nummer", "A"), ("Titel", "A"), ("Bewertung", "1,0")]),
        ])
        .unwrap();
        let b = canonicalize(&[
            rec(&[("Nummer", "A"), ("Titel", "A"), ("Bewertung", "1,0")]),
            rec(&[("Nummer", "B"), ("Titel", "B"), ("Bewertung", "2,0")]),
        ])
        .unwrap();
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn first_snapshot_does_not_notify() {
        let new = canonicalize(&[rec(&[
            ("Nummer", "IS-201"),
            ("Titel", "Datenbanken"),
            ("Bewertung", "1,7"),
        ])])
        .unwrap();
        let diff = diff_snapshots(None, None, &new).unwrap();
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn first_snapshot_can_emit_initial_new_results() {
        let new = canonicalize(&[
            rec(&[
                ("Nummer", "IS-201"),
                ("Titel", "Datenbanken"),
                ("Bewertung", "1,7"),
            ]),
            rec(&[
                ("Titel", "Structural group"),
                ("Bewertung", "ignored because no nummer"),
            ]),
            rec(&[
                ("Nummer", "IS-305"),
                ("Titel", "Algorithmen"),
                ("Bewertung", "2,0"),
            ]),
        ])
        .unwrap();

        let diff = diff_snapshots_with_initial(None, None, &new, true).unwrap();
        assert_eq!(diff.changes.len(), 2);
        assert!(
            diff.changes
                .iter()
                .all(|change| change.kind == ChangeKind::New)
        );
        assert!(diff.changes.iter().all(|change| change.old.is_none()));
        assert_eq!(diff.changes[0].nummer, "IS-201");
        assert_eq!(diff.changes[1].nummer, "IS-305");
    }

    #[test]
    fn account_rows_are_not_notifiable_snapshot_rows() {
        let new = canonicalize(&[
            rec(&[
                ("_row_kind", "Gesamtkonto"),
                ("Nummer", "8002-88-277-0-H-2025-K"),
                (
                    "Titel",
                    "vorläufige Durchschnittsnote | bisher erbrachte ECTS",
                ),
                ("Bewertung", "1.3"),
            ]),
            rec(&[
                ("_row_kind", "Prüfung"),
                ("Nummer", "IS-701"),
                ("Titel", "Data Mining"),
                ("Bewertung", "1.0"),
            ]),
        ])
        .unwrap();

        assert_eq!(new.rows.len(), 1);
        assert_eq!(new.rows[0].titel, "Data Mining");

        let diff = diff_snapshots_with_initial(None, None, &new, true).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].titel, "Data Mining");
    }

    #[test]
    fn legacy_account_rows_do_not_emit_removed_changes() {
        let old_payload = serde_json::to_string(&vec![SnapshotRow {
            key: "nummer:8002-88-277-0-H-2025-K".into(),
            nummer: "8002-88-277-0-H-2025-K".into(),
            titel: "vorläufige Durchschnittsnote | bisher erbrachte ECTS".into(),
            bewertung: "1.3".into(),
            status: "PV".into(),
            bonus: "6.0".into(),
        }])
        .unwrap();
        let new = canonicalize(&[]).unwrap();

        let diff =
            diff_snapshots(Some("legacy-account-hash".into()), Some(&old_payload), &new).unwrap();
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn detects_updates_and_suppresses_structural_only_changes() {
        let old = canonicalize(&[
            rec(&[("Titel", "Root")]),
            rec(&[
                ("Nummer", "IS-201"),
                ("Titel", "Datenbanken"),
                ("Bewertung", "2,0"),
                ("Status", "bestanden"),
            ]),
        ])
        .unwrap();
        let new = canonicalize(&[
            rec(&[("Titel", "Root renamed")]),
            rec(&[
                ("Nummer", "IS-201"),
                ("Titel", "Datenbanken"),
                ("Bewertung", "1,7"),
                ("Status", "bestanden"),
            ]),
        ])
        .unwrap();

        let diff = diff_snapshots(Some(old.hash), Some(&old.payload), &new).unwrap();
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, ChangeKind::Updated);
        assert_eq!(
            diff.changes[0].old.as_ref().unwrap().bewertung.as_str(),
            "2,0"
        );
        assert_eq!(
            diff.changes[0].new.as_ref().unwrap().bewertung.as_str(),
            "1,7"
        );
    }
}
