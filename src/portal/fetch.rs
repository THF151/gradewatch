use std::{io::Cursor, path::PathBuf, time::Duration};

use scraper::{Html, Selector};
use ureq::ResponseExt;
use url::Url;

use crate::{
    config::PortalConfig,
    error::GradeError,
    portal::{
        cas,
        debug::save_debug_html,
        parse::{GradeRecord, has_grades, parse_html_grades},
    },
};

const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#[derive(Debug, Clone)]
pub struct PortalClient {
    cfg: PortalConfig,
    connect_timeout: Duration,
    read_timeout: Duration,
    debug_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PortalFetchResult {
    pub records: Vec<GradeRecord>,
    pub session_json: Option<String>,
}

#[derive(Debug)]
struct PortalPage {
    html: String,
    final_url: String,
}

#[derive(Debug)]
struct ExpandAllRequest {
    action: String,
    fields: Vec<(String, String)>,
}

impl PortalClient {
    pub fn new(cfg: PortalConfig, connect_timeout: Duration, read_timeout: Duration) -> Self {
        Self {
            cfg,
            connect_timeout,
            read_timeout,
            debug_dir: None,
        }
    }

    pub fn with_debug_dir(mut self, debug_dir: impl Into<PathBuf>) -> Self {
        self.debug_dir = Some(debug_dir.into());
        self
    }

    pub fn fetch_records(
        &self,
        username: &str,
        password: &str,
        session_json: Option<&str>,
    ) -> Result<PortalFetchResult, GradeError> {
        let agent = self.agent();
        if let Some(session_json) = session_json {
            load_cookies(&agent, session_json)?;
        }

        let mut page = self.fetch_leistungen_page(&agent)?;
        if !has_grades(&page.html) {
            tracing::info!("no valid cached portal session; starting CAS login");
            cas::login(
                &agent,
                &self.cfg,
                username,
                password,
                self.debug_dir.as_deref(),
            )?;
            page = self.fetch_leistungen_page(&agent)?;
        }
        if !has_grades(&page.html) {
            self.save_debug("leistungen_unexpected", &page.html);
            return Err(GradeError::Parse(
                "logged in but grades page did not contain expected table markers".into(),
            ));
        }

        let html = self
            .expand_all_if_possible(&agent, &page.html, &page.final_url)?
            .unwrap_or(page.html);
        let records = parse_html_grades(&html).inspect_err(|_| {
            self.save_debug("leistungen_parse_failed", &html);
        })?;
        let session_json = save_cookies(&agent)?;
        Ok(PortalFetchResult {
            records,
            session_json,
        })
    }

    pub fn fetch_leistungen_html_after_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, GradeError> {
        let agent = self.agent();
        cas::login(
            &agent,
            &self.cfg,
            username,
            password,
            self.debug_dir.as_deref(),
        )?;
        Ok(self.fetch_leistungen_page(&agent)?.html)
    }

    fn agent(&self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .accept_encoding("gzip")
            .timeout_connect(Some(self.connect_timeout))
            .timeout_recv_response(Some(self.read_timeout))
            .timeout_recv_body(Some(self.read_timeout))
            .timeout_per_call(Some(
                self.connect_timeout + self.read_timeout + Duration::from_secs(5),
            ))
            .max_redirects(10)
            .build()
            .into()
    }

    fn fetch_leistungen_page(&self, agent: &ureq::Agent) -> Result<PortalPage, GradeError> {
        let mut response = agent
            .get(&self.cfg.leistungen_url)
            .config()
            .http_status_as_error(false)
            .build()
            .call()?;
        let status = response.status();
        let final_url = response.get_uri().to_string();
        response
            .body_mut()
            .read_to_string()
            .map_err(Into::into)
            .inspect(|html| {
                tracing::debug!(
                    status = status.as_u16(),
                    final_url = %final_url,
                    bytes = html.len(),
                    has_grades = has_grades(html),
                    "fetched portal grades page"
                );
                if !has_grades(html) && (status.is_client_error() || status.is_server_error()) {
                    self.save_debug("leistungen_no_grades", html);
                }
            })
            .map(|html| PortalPage { html, final_url })
    }

    fn expand_all_if_possible(
        &self,
        agent: &ureq::Agent,
        html: &str,
        final_url: &str,
    ) -> Result<Option<String>, GradeError> {
        let Some(request) = expand_all_request(html, final_url)? else {
            tracing::debug!("portal page did not expose an expand-all control");
            return Ok(None);
        };

        tracing::debug!(action = %request.action, "POST portal expand-all control");
        let mut response = agent
            .post(&request.action)
            .header("Referer", final_url)
            .send_form(request.fields)?;
        let status = response.status();
        let expanded_url = response.get_uri().to_string();
        let body = response.body_mut().read_to_string()?;
        let expanded = extract_partial_update_html(&body).unwrap_or(body);
        tracing::debug!(
            status = status.as_u16(),
            final_url = %expanded_url,
            bytes = expanded.len(),
            has_grades = has_grades(&expanded),
            "received portal expand-all response"
        );

        if has_grades(&expanded) {
            Ok(Some(expanded))
        } else {
            tracing::warn!(
                "portal expand-all response did not contain grades table; using original page"
            );
            self.save_debug("leistungen_expand_all_unexpected", &expanded);
            Ok(None)
        }
    }

    fn save_debug(&self, name: &str, html: &str) {
        save_debug_html(self.debug_dir.as_deref(), name, html);
    }
}

fn expand_all_request(html: &str, base_url: &str) -> Result<Option<ExpandAllRequest>, GradeError> {
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form")
        .map_err(|e| GradeError::Parse(format!("invalid form selector: {e}")))?;
    let button_selector =
        Selector::parse(r#"button[name$=":expandAll2"], button[id$=":expandAll2"]"#)
            .map_err(|e| GradeError::Parse(format!("invalid expand button selector: {e}")))?;
    let input_selector = Selector::parse("input")
        .map_err(|e| GradeError::Parse(format!("invalid input selector: {e}")))?;

    for form in document.select(&form_selector) {
        let Some(button) = form.select(&button_selector).next() else {
            continue;
        };
        let Some(button_name) = button
            .value()
            .attr("name")
            .or_else(|| button.value().attr("id"))
        else {
            continue;
        };
        let button_value = button.value().attr("value").unwrap_or_default();
        let base = Url::parse(base_url)
            .map_err(|e| GradeError::Parse(format!("invalid portal page URL {base_url}: {e}")))?;
        let action = form
            .value()
            .attr("action")
            .map(|action| base.join(action))
            .transpose()
            .map_err(|e| GradeError::Parse(format!("invalid portal form action: {e}")))?
            .unwrap_or(base)
            .to_string();

        let mut fields = Vec::new();
        for input in form.select(&input_selector) {
            if input.value().attr("disabled").is_some() {
                continue;
            }
            let Some(name) = input.value().attr("name") else {
                continue;
            };
            let input_type = input
                .value()
                .attr("type")
                .unwrap_or("text")
                .to_ascii_lowercase();
            if matches!(input_type.as_str(), "submit" | "button" | "image" | "file") {
                continue;
            }
            if matches!(input_type.as_str(), "checkbox" | "radio")
                && input.value().attr("checked").is_none()
            {
                continue;
            }
            fields.push((
                name.to_string(),
                input.value().attr("value").unwrap_or_default().to_string(),
            ));
        }
        fields.push((button_name.to_string(), button_value.to_string()));

        return Ok(Some(ExpandAllRequest { action, fields }));
    }

    Ok(None)
}

fn extract_partial_update_html(body: &str) -> Option<String> {
    if !body.contains("<partial-response") {
        return None;
    }

    let mut best = None::<String>;
    let mut rest = body;
    while let Some(start) = rest.find("<![CDATA[") {
        let after_start = &rest[start + "<![CDATA[".len()..];
        let Some(end) = after_start.find("]]>") else {
            break;
        };
        let candidate = &after_start[..end];
        select_partial_candidate(&mut best, candidate.to_string());
        rest = &after_start[end + "]]>".len()..];
    }

    let mut rest = body;
    while let Some(start) = rest.find("<update") {
        let after_start = &rest[start..];
        let Some(tag_end) = after_start.find('>') else {
            break;
        };
        let after_tag = &after_start[tag_end + 1..];
        let Some(end) = after_tag.find("</update>") else {
            break;
        };
        let decoded = html_escape::decode_html_entities(&after_tag[..end]).to_string();
        select_partial_candidate(&mut best, decoded);
        rest = &after_tag[end + "</update>".len()..];
    }

    best
}

fn select_partial_candidate(best: &mut Option<String>, candidate: String) {
    if candidate.contains("treeTableWithIcons")
        && candidate.contains("Bewertung")
        && best
            .as_ref()
            .is_none_or(|current| candidate.len() > current.len())
    {
        *best = Some(candidate);
    }
}

fn load_cookies(agent: &ureq::Agent, session_json: &str) -> Result<(), GradeError> {
    if session_json.trim().is_empty() {
        return Ok(());
    }
    let mut jar = agent.cookie_jar_lock();
    let result = jar.load_json(Cursor::new(session_json.as_bytes()));
    jar.release();
    result.map_err(|e| GradeError::Network(format!("could not load cached cookies: {e}")))
}

fn save_cookies(agent: &ureq::Agent) -> Result<Option<String>, GradeError> {
    let mut out = Vec::new();
    let jar = agent.cookie_jar_lock();
    let result = jar.save_json(&mut out);
    jar.release();
    result.map_err(|e| GradeError::Network(format!("could not save cached cookies: {e}")))?;
    if out.is_empty() || out == b"[]" {
        Ok(None)
    } else {
        String::from_utf8(out)
            .map(Some)
            .map_err(|e| GradeError::Network(format!("cookie JSON was not UTF-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn builds_expand_all_form_post_from_portal_markup() {
        let request = expand_all_request(
            r#"
            <form id="examsReadonly" name="examsReadonly" method="post"
                  action="/portal2/pages/sul/examAssessment/personExamsReadonly.xhtml?_flowId=examsOverviewForPerson-flow&amp;_flowExecutionKey=e1s1">
              <input type="hidden" name="activePageElementId" value="">
              <input type="hidden" name="authenticity_token" value="token">
              <input type="hidden" name="examsReadonly_SUBMIT" value="1">
              <input type="hidden" name="javax.faces.ViewState" value="e1s1">
              <button id="examsReadonly:overviewAsTreeReadonly:tree:expandAll2"
                      name="examsReadonly:overviewAsTreeReadonly:tree:expandAll2"
                      type="submit"
                      value="Alle aufklappen">Alle aufklappen</button>
            </form>
            "#,
            "https://portal2.uni-mannheim.de/portal2/pages/sul/examAssessment/personExamsReadonly.xhtml?_flowId=examsOverviewForPerson-flow",
        )
        .unwrap()
        .expect("expand-all request is present");

        assert_eq!(
            request.action,
            "https://portal2.uni-mannheim.de/portal2/pages/sul/examAssessment/personExamsReadonly.xhtml?_flowId=examsOverviewForPerson-flow&_flowExecutionKey=e1s1"
        );
        assert_eq!(field(&request.fields, "authenticity_token"), Some("token"));
        assert_eq!(
            field(&request.fields, "javax.faces.ViewState"),
            Some("e1s1")
        );
        assert_eq!(
            field(
                &request.fields,
                "examsReadonly:overviewAsTreeReadonly:tree:expandAll2"
            ),
            Some("Alle aufklappen")
        );
    }

    #[test]
    fn extracts_grades_table_from_jsf_partial_response() {
        let html = extract_partial_update_html(
            r#"
            <partial-response><changes>
              <update id="small"><![CDATA[<span>ignore</span>]]></update>
              <update id="grades"><![CDATA[
                <div id="tree">
                  <table class="treeTableWithIcons"><tr><th>Bewertung</th></tr><tr><td>1</td></tr></table>
                </div>
              ]]></update>
            </changes></partial-response>
            "#,
        )
        .expect("partial response contains grades table");

        assert!(html.contains("treeTableWithIcons"));
        assert!(html.contains("Bewertung"));
    }

    #[test]
    fn extracts_html_entity_encoded_jsf_update() {
        let html = extract_partial_update_html(
            r#"
            <partial-response><changes>
              <update id="grades">&lt;table class=&quot;treeTableWithIcons&quot;&gt;&lt;tr&gt;&lt;th&gt;Bewertung&lt;/th&gt;&lt;/tr&gt;&lt;/table&gt;</update>
            </changes></partial-response>
            "#,
        )
        .expect("partial response contains encoded grades table");

        assert!(html.contains("treeTableWithIcons"));
        assert!(html.contains("Bewertung"));
    }
}
