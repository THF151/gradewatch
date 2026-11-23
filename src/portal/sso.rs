//! Portal2 login through the Uni Mannheim Shibboleth IdP (SAML 2.0).
//!
//! Portal2 no longer accepts CAS service tickets. Students and staff with a
//! Uni-ID now sign in via `/portal2/api/identityprovider/redirect/<id>/login`,
//! which sends a signed SAML AuthnRequest to `idp.uni-mannheim.de`. The IdP
//! shows a `j_username`/`j_password` form, answers a successful login with an
//! auto-submitting form that POSTs `SAMLResponse` and `RelayState` back to the
//! Portal2 assertion consumer service, and Portal2 then sets its session
//! cookie.
//!
//! Browsers submit that last form with JavaScript, so this module walks the
//! same steps by hand. Credentials are submitted at most once per login, so a
//! wrong password can never be retried into an account lockout.

use std::{collections::BTreeSet, path::Path};

use scraper::{ElementRef, Html, Selector};
use ureq::ResponseExt;
use url::Url;

use crate::{config::PortalConfig, error::GradeError, portal::debug::save_debug_html};

/// Upper bound on IdP pages handled in one login (form, interstitials, SAML
/// POST). The real flow needs three.
const MAX_STEPS: usize = 6;

pub fn login(
    agent: &ureq::Agent,
    cfg: &PortalConfig,
    username: &str,
    password: &str,
    debug_dir: Option<&Path>,
) -> Result<(), GradeError> {
    let start_url = Url::parse(&cfg.sso_login_url)
        .map_err(|e| GradeError::Config(format!("invalid PORTAL_SSO_LOGIN_URL: {e}")))?;
    let service_host = host_of(start_url.as_str())
        .ok_or_else(|| GradeError::Config("PORTAL_SSO_LOGIN_URL has no host".into()))?;

    tracing::debug!(url = %start_url, "GET Portal2 SSO login redirect");
    let mut page = Page::read(agent.get(start_url.as_str()).call()?)?;
    let mut credentials_sent = false;
    let mut visited = BTreeSet::new();

    for step in 0..MAX_STEPS {
        tracing::debug!(
            step,
            status = page.status,
            final_url = %page.url,
            bytes = page.html.len(),
            "received SSO page"
        );

        match classify(&page.html, &page.url)? {
            SsoPage::SamlResponse(form) => {
                ensure_host(&form.action, &service_host, "SAML assertion")?;
                tracing::debug!(action = %form.action, "POST SAML response to Portal2");
                page = Page::read(agent.post(form.action.as_str()).send_form(form.fields)?)?;
                if host_of(&page.url).as_deref() != Some(service_host.as_str()) {
                    save_debug_html(debug_dir, "sso_acs_unexpected", &page.html);
                    return Err(GradeError::Auth(format!(
                        "Portal2 did not accept the SAML response (ended at {})",
                        page.url
                    )));
                }
                return Ok(());
            }
            SsoPage::Credentials {
                form,
                user_field,
                pass_field,
            } => {
                if credentials_sent {
                    save_debug_html(debug_dir, "sso_login_failed", &page.html);
                    return Err(GradeError::Auth(format!(
                        "SSO login failed: {}",
                        extract_error_text(&page.html).unwrap_or_else(|| {
                            "check Uni-ID credentials or 2FA requirements".into()
                        })
                    )));
                }
                ensure_host(
                    &form.action,
                    &host_of(&page.url).unwrap_or_default(),
                    "credentials",
                )?;
                let mut fields = form.fields;
                fields.push((user_field, username.to_string()));
                fields.push((pass_field, password.to_string()));
                tracing::debug!(
                    action = %form.action,
                    fields = %field_names(&fields),
                    username_len = username.len(),
                    password_len = password.len(),
                    "POST SSO credentials"
                );
                credentials_sent = true;
                page = Page::read(agent.post(form.action.as_str()).send_form(fields)?)?;
            }
            SsoPage::Proceed(form) => {
                // Shibboleth interceptors (attribute release consent, password
                // expiry notices) offer a single "proceed" event. Submit each
                // one once, so a page that keeps coming back cannot loop.
                if !visited.insert(form.action.clone()) {
                    save_debug_html(debug_dir, "sso_proceed_loop", &page.html);
                    return Err(GradeError::Auth(
                        "SSO login stuck on an IdP confirmation page".into(),
                    ));
                }
                ensure_host(
                    &form.action,
                    &host_of(&page.url).unwrap_or_default(),
                    "IdP confirmation",
                )?;
                tracing::debug!(action = %form.action, fields = %field_names(&form.fields), "POST SSO proceed");
                page = Page::read(agent.post(form.action.as_str()).send_form(form.fields)?)?;
            }
            SsoPage::Unknown => {
                if credentials_sent && host_of(&page.url).as_deref() == Some(service_host.as_str())
                {
                    // An existing IdP session can hand the browser straight
                    // back to Portal2 without a visible SAML form.
                    return Ok(());
                }
                save_debug_html(debug_dir, "sso_no_form", &page.html);
                return Err(GradeError::Auth(format!(
                    "SSO login form not found at {}",
                    page.url
                )));
            }
        }
    }

    save_debug_html(debug_dir, "sso_too_many_steps", &page.html);
    Err(GradeError::Auth(format!(
        "SSO login did not finish after {MAX_STEPS} steps (last page {})",
        page.url
    )))
}

struct Page {
    status: u16,
    url: String,
    html: String,
}

impl Page {
    fn read(mut response: ureq::http::Response<ureq::Body>) -> Result<Self, GradeError> {
        let status = response.status().as_u16();
        let url = response.get_uri().to_string();
        let html = response.body_mut().read_to_string()?;
        Ok(Self { status, url, html })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FormPost {
    action: String,
    fields: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
enum SsoPage {
    /// Auto-submitting form that carries the SAML assertion back to Portal2.
    SamlResponse(FormPost),
    /// IdP username/password form. `form.fields` holds everything except the
    /// two credential fields, whose names are returned separately.
    Credentials {
        form: FormPost,
        user_field: String,
        pass_field: String,
    },
    /// IdP interstitial with a `_eventId_proceed` submit button.
    Proceed(FormPost),
    Unknown,
}

fn classify(html: &str, base_url: &str) -> Result<SsoPage, GradeError> {
    let document = Html::parse_document(html);
    let base = Url::parse(base_url)
        .map_err(|e| GradeError::Auth(format!("SSO returned invalid URL {base_url}: {e}")))?;
    let forms = selector("form")?;
    let inputs = selector("input")?;
    let buttons = selector(
        r#"button[name="_eventId_proceed"], input[type="submit"][name="_eventId_proceed"]"#,
    )?;

    let mut proceed = None;
    for form in document.select(&forms) {
        let named = |name: &str| {
            form.select(&inputs)
                .any(|input| input.value().attr("name") == Some(name))
        };
        if named("SAMLResponse") {
            return Ok(SsoPage::SamlResponse(form_post(
                form, &base, &inputs, None,
            )?));
        }

        let pass_field = form
            .select(&inputs)
            .find(|input| input_type(input) == "password")
            .and_then(|input| input.value().attr("name"));
        if let Some(pass_field) = pass_field {
            let user_field = form
                .select(&inputs)
                .find(|input| matches!(input_type(input).as_str(), "text" | "email"))
                .and_then(|input| input.value().attr("name"))
                .ok_or_else(|| GradeError::Auth("SSO login form has no username field".into()))?;
            let submit = form.select(&buttons).next();
            let mut form_post = form_post(form, &base, &inputs, submit)?;
            form_post
                .fields
                .retain(|(name, _)| name != user_field && name != pass_field);
            return Ok(SsoPage::Credentials {
                form: form_post,
                user_field: user_field.to_string(),
                pass_field: pass_field.to_string(),
            });
        }

        if proceed.is_none()
            && let Some(submit) = form.select(&buttons).next()
        {
            proceed = Some(form_post(form, &base, &inputs, Some(submit))?);
        }
    }

    Ok(proceed.map_or(SsoPage::Unknown, SsoPage::Proceed))
}

/// Builds the request a browser would send for `form`: hidden and text
/// inputs, checked checkboxes and radios, and the clicked submit button.
fn form_post(
    form: ElementRef<'_>,
    base: &Url,
    inputs: &Selector,
    submit: Option<ElementRef<'_>>,
) -> Result<FormPost, GradeError> {
    let action = match form.value().attr("action") {
        Some(action) => base
            .join(&html_escape::decode_html_entities(action))
            .map_err(|e| GradeError::Auth(format!("SSO form action was invalid: {e}")))?,
        None => base.clone(),
    };

    let mut fields = Vec::new();
    for input in form.select(inputs) {
        let Some(name) = input.value().attr("name") else {
            continue;
        };
        if input.value().attr("disabled").is_some() {
            continue;
        }
        match input_type(&input).as_str() {
            "submit" | "button" | "image" | "file" | "reset" => continue,
            "checkbox" | "radio" if input.value().attr("checked").is_none() => continue,
            _ => {}
        }
        fields.push((
            name.to_string(),
            input.value().attr("value").unwrap_or_default().to_string(),
        ));
    }
    if let Some(submit) = submit
        && let Some(name) = submit.value().attr("name")
    {
        fields.push((
            name.to_string(),
            submit.value().attr("value").unwrap_or_default().to_string(),
        ));
    }

    Ok(FormPost {
        action: action.to_string(),
        fields,
    })
}

fn input_type(input: &ElementRef<'_>) -> String {
    input
        .value()
        .attr("type")
        .unwrap_or("text")
        .to_ascii_lowercase()
}

fn selector(css: &str) -> Result<Selector, GradeError> {
    Selector::parse(css).map_err(|e| GradeError::Parse(format!("invalid selector {css}: {e}")))
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()?
        .host_str()
        .map(str::to_ascii_lowercase)
}

/// Refuses to send `what` anywhere but `expected_host`, so a tampered or
/// unexpected page cannot redirect credentials or the SAML assertion.
fn ensure_host(action: &str, expected_host: &str, what: &str) -> Result<(), GradeError> {
    match host_of(action) {
        Some(host) if !expected_host.is_empty() && host.eq_ignore_ascii_case(expected_host) => {
            Ok(())
        }
        _ => Err(GradeError::Auth(format!(
            "refusing to send {what} to {action}: expected host {expected_host}"
        ))),
    }
}

fn field_names(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn extract_error_text(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    [
        ".output--error",
        ".form-error",
        ".errors",
        ".alert",
        ".login-error",
        "[role=alert]",
    ]
    .iter()
    .filter_map(|css| Selector::parse(css).ok())
    .find_map(|css| {
        document.select(&css).next().map(|element| {
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

    const IDP_URL: &str =
        "https://idp.uni-mannheim.de/idp/profile/SAML2/Redirect/SSO?execution=e1s1";

    // Trimmed copy of the live IdP login form (November 2026).
    const IDP_FORM: &str = r#"
        <form id="login-form" class="fm-v clearfix" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s1" method="post">
          <input type="hidden" name="csrf_token" value="_abc" />
          <input class="form-control" id="username" name="j_username" value="" type="text" required="required" />
          <input type="password" id="password" name="j_password" value="" required="required" />
          <input id="donotcache" name="donotcache" value="1" type="checkbox">
          <input id="_shib_idp_revokeConsent" type="checkbox" name="_shib_idp_revokeConsent" value="true">
          <button class="button" id="login-submit" type="submit" name="_eventId_proceed">Anmelden</button>
        </form>"#;

    fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn recognises_idp_credentials_form() {
        let SsoPage::Credentials {
            form,
            user_field,
            pass_field,
        } = classify(IDP_FORM, IDP_URL).unwrap()
        else {
            panic!("expected credentials form");
        };
        assert_eq!(
            form.action,
            "https://idp.uni-mannheim.de/idp/profile/SAML2/Redirect/SSO?execution=e1s1"
        );
        assert_eq!(user_field, "j_username");
        assert_eq!(pass_field, "j_password");
        assert_eq!(field(&form.fields, "csrf_token"), Some("_abc"));
        assert_eq!(field(&form.fields, "_eventId_proceed"), Some(""));
        assert_eq!(
            field(&form.fields, "donotcache"),
            None,
            "unchecked box is not sent"
        );
        assert_eq!(field(&form.fields, "_shib_idp_revokeConsent"), None);
        assert_eq!(field(&form.fields, "j_username"), None);
    }

    #[test]
    fn recognises_saml_auto_post_form() {
        let page = classify(
            r#"<body onload="document.forms[0].submit()">
                 <form action="https&#x3a;&#x2f;&#x2f;portal2.uni-mannheim.de&#x2f;portal2&#x2f;api&#x2f;v1&#x2f;cs&#x2f;psv&#x2f;callback&#x2f;saml" method="post">
                   <input type="hidden" name="RelayState" value="login.idpId=4.xyz"/>
                   <input type="hidden" name="SAMLResponse" value="PD94bWw="/>
                   <input type="submit" value="Continue"/>
                 </form></body>"#,
            "https://idp.uni-mannheim.de/idp/profile/SAML2/Redirect/SSO?execution=e1s2",
        )
        .unwrap();
        let SsoPage::SamlResponse(form) = page else {
            panic!("expected SAML response form, got {page:?}");
        };
        assert_eq!(
            form.action,
            "https://portal2.uni-mannheim.de/portal2/api/v1/cs/psv/callback/saml"
        );
        assert_eq!(field(&form.fields, "SAMLResponse"), Some("PD94bWw="));
        assert_eq!(field(&form.fields, "RelayState"), Some("login.idpId=4.xyz"));
        assert_eq!(form.fields.len(), 2);
    }

    #[test]
    fn recognises_proceed_interstitial() {
        let page = classify(
            r#"<form action="/idp/profile/SAML2/Redirect/SSO?execution=e1s3" method="post">
                 <input type="hidden" name="csrf_token" value="_t">
                 <input type="radio" name="_shib_idp_consentOptions" value="_shib_idp_rememberConsent" checked>
                 <input type="radio" name="_shib_idp_consentOptions" value="_shib_idp_doNotRememberConsent">
                 <input type="submit" name="_eventId_AttributeReleaseRejected" value="Reject">
                 <input type="submit" name="_eventId_proceed" value="Accept">
               </form>"#,
            IDP_URL,
        )
        .unwrap();
        let SsoPage::Proceed(form) = page else {
            panic!("expected proceed form, got {page:?}");
        };
        assert_eq!(
            form.fields,
            vec![
                ("csrf_token".into(), "_t".into()),
                (
                    "_shib_idp_consentOptions".into(),
                    "_shib_idp_rememberConsent".into()
                ),
                ("_eventId_proceed".into(), "Accept".into()),
            ]
        );
    }

    #[test]
    fn retired_cas_error_page_is_unknown() {
        let page = classify(
            r#"<div id="msg" class="errors"><h1>Applikation nicht berechtigt CAS zu verwenden</h1></div>"#,
            "https://cas.uni-mannheim.de/cas/login?service=x",
        )
        .unwrap();
        assert_eq!(page, SsoPage::Unknown);
    }

    #[test]
    fn extracts_idp_failure_message() {
        let html = format!(
            r#"<p class="error output-message output--error">Anmeldung fehlgeschlagen.</p>{IDP_FORM}"#
        );
        assert_eq!(
            extract_error_text(&html).as_deref(),
            Some("Anmeldung fehlgeschlagen.")
        );
    }

    #[test]
    fn host_guard_rejects_foreign_targets() {
        assert!(
            ensure_host(
                "https://portal2.uni-mannheim.de/acs",
                "portal2.uni-mannheim.de",
                "x"
            )
            .is_ok()
        );
        assert!(ensure_host("http://127.0.0.1:8080/acs", "127.0.0.1", "x").is_ok());
        assert!(ensure_host("https://evil.example/acs", "portal2.uni-mannheim.de", "x").is_err());
        assert!(
            ensure_host(
                "https://portal2.uni-mannheim.de@evil.example/",
                "portal2.uni-mannheim.de",
                "x"
            )
            .is_err()
        );
        assert!(ensure_host("https://idp.uni-mannheim.de/x", "", "x").is_err());
    }
}
