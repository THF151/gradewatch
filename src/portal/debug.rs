use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn save_debug_html(debug_dir: Option<&Path>, name: &str, html: &str) {
    let Some(dir) = debug_dir else {
        return;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let path = dir.join(format!("{name}_{stamp}.html"));
    let _ = std::fs::write(&path, html);
    tracing::debug!(path = %path.display(), "saved portal debug HTML");
}
