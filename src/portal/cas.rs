use std::path::Path;

use scraper::{Html, Selector};
use ureq::ResponseExt;
use url::Url;

use crate::{config::PortalConfig, error::GradeError, portal::debug::save_debug_html};

pub fn login(
    agent: &ureq::Agent,
    cfg: &PortalConfig,
    username: &str,
    password: &str,
    debug_dir: Option<&Path>,
) -> Result<(), GradeError> {
    let login_url = cas_login_url(cfg)?;
    tracing::debug!(url = %login_url, "GET CAS login form");
    let mut response = agent.get(login_url.as_str()).call()?;
    let status = response.status();
    let form_url = response.get_uri().to_string();
    let html = response.body_mut().read_to_string()?;
    tracing::debug!(
        status = status.as_u16(),
        final_url = %form_url,
        bytes = html.len(),
        "received CAS login form response"
    );
    let (action, mut payload) = parse_login_form(&html, &form_url).inspect_err(|_| {
        save_debug_html(debug_dir, "cas_no_form", &html);
    })?;
    payload.insert("username".into(), username.into());
    payload.insert("password".into(), password.into());
    payload
        .entry("_eventId".into())
        .or_insert_with(|| "submit".into());

    let field_names = payload.keys().cloned().collect::<Vec<_>>().join(",");
    tracing::debug!(
        action = %action,
        fields = %field_names,
        username_len = username.len(),
        password_len = password.len(),
        "POST CAS credentials"
    );
    let form = payload.into_iter().collect::<Vec<_>>();
    let mut response = agent.post(action.as_str()).send_form(form)?;
    let status = response.status();
    let final_url = response.get_uri().to_string();
    tracing::debug!(
        status = status.as_u16(),
        final_url = %final_url,
        "received CAS credential POST response"
    );
    if final_url.contains("cas.uni-mannheim.de") || final_url.contains("/cas/login") {
        let html = response.body_mut().read_to_string().unwrap_or_default();
        save_debug_html(debug_dir, "cas_login_failed", &html);
        return Err(GradeError::Auth(format!(
            "CAS login failed: {}",
            extract_error_text(&html)
                .unwrap_or_else(|| "check credentials or 2FA requirements".to_string())
        )));
    }

    Ok(())
}

fn cas_login_url(cfg: &PortalConfig) -> Result<Url, GradeError> {
    let mut url = Url::parse(&cfg.cas_login_url)
        .map_err(|e| GradeError::Config(format!("invalid PORTAL_CAS_LOGIN_URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("service", &cfg.service_url);
    Ok(url)
}

fn parse_login_form(
    html: &str,
    base_url: &str,
) -> Result<(String, std::collections::BTreeMap<String, String>), GradeError> {
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form")
        .map_err(|e| GradeError::Parse(format!("invalid form selector: {e}")))?;
    let input_selector = Selector::parse("input")
        .map_err(|e| GradeError::Parse(format!("invalid input selector: {e}")))?;
    let form = document
        .select(&form_selector)
        .next()
        .ok_or_else(|| GradeError::Auth("CAS login form not found".into()))?;

    let base = Url::parse(base_url)
        .map_err(|e| GradeError::Auth(format!("CAS returned invalid URL {base_url}: {e}")))?;
    let action = form
        .value()
        .attr("action")
        .map(|action| base.join(action))
        .transpose()
        .map_err(|e| GradeError::Auth(format!("CAS form action was invalid: {e}")))?
        .unwrap_or(base)
        .to_string();

    let mut payload = std::collections::BTreeMap::new();
    for input in form.select(&input_selector) {
        if let Some(name) = input.value().attr("name") {
            payload.insert(
                name.to_string(),
                input.value().attr("value").unwrap_or_default().to_string(),
            );
        }
    }
    Ok((action, payload))
}

fn extract_error_text(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    [".errors", ".alert", ".login-error", "[role=alert]"]
        .iter()
        .filter_map(|selector| Selector::parse(selector).ok())
        .find_map(|selector| {
            document.select(&selector).next().map(|element| {
                element
                    .text()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        })
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hidden_fields_and_resolves_action() {
        let (action, payload) = parse_login_form(
            r#"<form action="/cas/login;jsessionid=abc">
                 <input name="execution" value="e1s1">
                 <input name="_eventId" value="submit">
               </form>"#,
            "https://cas.uni-mannheim.de/cas/login?service=x",
        )
        .unwrap();

        assert_eq!(
            action,
            "https://cas.uni-mannheim.de/cas/login;jsessionid=abc"
        );
        assert_eq!(payload.get("execution").unwrap(), "e1s1");
    }
}
