use std::time::{Duration, SystemTime};

pub fn format_system_time_utc(time: SystemTime) -> String {
    jiff::Timestamp::try_from(time)
        .map(|timestamp| timestamp.strftime("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|_| "unrepresentable time".into())
}

pub fn relative_from_now(time: SystemTime, now: SystemTime) -> String {
    match time.duration_since(now) {
        Ok(duration) if duration.is_zero() => "now".into(),
        Ok(duration) => format!("in {}", format_duration(duration)),
        Err(err) => format!("{} ago", format_duration(err.duration())),
    }
}

pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }

    let minutes = secs / 60;
    let seconds = secs % 60;
    if minutes < 60 {
        return if seconds == 0 {
            format!("{minutes}m")
        } else {
            format!("{minutes}m {seconds}s")
        };
    }

    let hours = minutes / 60;
    let minutes = minutes % 60;
    if hours < 24 {
        return if minutes == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h {minutes}m")
        };
    }

    let days = hours / 24;
    let hours = hours % 24;
    if hours == 0 {
        format!("{days}d")
    } else {
        format!("{days}d {hours}h")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_relative_durations_compactly() {
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(90_000)), "1d 1h");
    }
}
