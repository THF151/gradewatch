//! Simulates the Portal2 Shibboleth login against a local mock server:
//! Portal2 redirect -> IdP login form -> credential POST -> auto-submitting
//! SAML response form -> Portal2 assertion consumer service -> grades page.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use gradewatch::error::GradeError;
use gradewatch::{config::PortalConfig, portal::fetch::PortalClient};
use tiny_http::{Header, Method, Response, Server, StatusCode};

const IDP_FORM: &str = r#"
    <form id="login-form" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s1" method="post">
      <input type="hidden" name="csrf_token" value="_csrf1" />
      <input id="username" name="j_username" value="" type="text" />
      <input type="password" id="password" name="j_password" value="" />
      <input id="donotcache" name="donotcache" value="1" type="checkbox">
      <button id="login-submit" type="submit" name="_eventId_proceed">Anmelden</button>
    </form>"#;

#[derive(Clone, Copy)]
enum Scenario {
    Success { fixture: &'static str },
    WrongPassword,
    AcsOnForeignHost,
}

struct Mock {
    base: String,
    credential_posts: Arc<AtomicUsize>,
    handle: thread::JoinHandle<()>,
}

fn spawn_mock(scenario: Scenario) -> Mock {
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let base = format!("http://{addr}");
    let credential_posts = Arc::new(AtomicUsize::new(0));
    let posts = Arc::clone(&credential_posts);

    let handle = thread::spawn(move || {
        let mut authed_grade_hits = 0;
        while let Ok(Some(mut request)) = server.recv_timeout(Duration::from_secs(2)) {
            let path = request.url().to_string();
            let method = request.method().clone();
            let cookie = request
                .headers()
                .iter()
                .find(|h| h.field.equiv("Cookie"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();

            let response = match (&method, path.as_str()) {
                (Method::Get, p) if p.starts_with("/leistungen") => {
                    if cookie.contains("portal_session=ok") {
                        authed_grade_hits += 1;
                        let Scenario::Success { fixture } = scenario else {
                            unreachable!()
                        };
                        html_response(fixture)
                    } else {
                        html_response("<html>not logged in</html>")
                            .with_status_code(StatusCode(403))
                    }
                }
                // Portal2: start the SAML login.
                (Method::Get, "/portal2/api/identityprovider/redirect/4/login") => {
                    redirect("/idp/profile/SAML2/Redirect/SSO?SAMLRequest=abc&RelayState=r1")
                        .with_header(header("Set-Cookie", "JSESSIONID=pre; Path=/"))
                }
                // IdP: begin the web flow, then show the form.
                (Method::Get, p) if p.contains("SAMLRequest=") => {
                    redirect("/idp/profile/SAML2/Redirect/SSO?execution=e1s1")
                        .with_header(header("Set-Cookie", "__Host-JSESSIONID=idp; Path=/"))
                }
                (Method::Get, "/idp/profile/SAML2/Redirect/SSO?execution=e1s1") => {
                    html_response(IDP_FORM)
                }
                (Method::Post, "/idp/profile/SAML2/Redirect/SSO?execution=e1s1") => {
                    posts.fetch_add(1, Ordering::SeqCst);
                    let mut body = String::new();
                    request.as_reader().read_to_string(&mut body).unwrap();
                    assert!(body.contains("j_username=uni-user"), "{body}");
                    assert!(body.contains("csrf_token=_csrf1"), "{body}");
                    assert!(body.contains("_eventId_proceed="), "{body}");
                    assert!(!body.contains("donotcache"), "{body}");
                    match scenario {
                        Scenario::WrongPassword => html_response(&format!(
                            r#"<p class="error output-message output--error">Anmeldung fehlgeschlagen.</p>
                               {}"#,
                            IDP_FORM.replace("e1s1", "e1s2")
                        )),
                        _ => {
                            assert!(body.contains("j_password=uni-pass"), "{body}");
                            let acs = match scenario {
                                Scenario::AcsOnForeignHost => {
                                    "http://evil.invalid/portal2/api/v1/cs/psv/callback/saml"
                                        .to_string()
                                }
                                _ => format!("http://{addr}/portal2/api/v1/cs/psv/callback/saml"),
                            };
                            html_response(&format!(
                                r#"<body onload="document.forms[0].submit()">
                                     <form action="{acs}" method="post">
                                       <input type="hidden" name="RelayState" value="login.idpId=4.r1"/>
                                       <input type="hidden" name="SAMLResponse" value="PD94bWw="/>
                                       <input type="submit" value="Continue"/>
                                     </form></body>"#
                            ))
                        }
                    }
                }
                // Portal2 assertion consumer service.
                (Method::Post, "/portal2/api/v1/cs/psv/callback/saml") => {
                    let mut body = String::new();
                    request.as_reader().read_to_string(&mut body).unwrap();
                    assert!(body.contains("SAMLResponse=PD94bWw%3D"), "{body}");
                    assert!(body.contains("RelayState=login.idpId%3D4.r1"), "{body}");
                    redirect("/portal2/pages/cs/sys/portal/hisinoneStartPage.faces")
                        .with_header(header("Set-Cookie", "portal_session=ok; Path=/"))
                }
                (Method::Get, "/portal2/pages/cs/sys/portal/hisinoneStartPage.faces") => {
                    html_response("<html>Startseite</html>")
                }
                _ => Response::from_string("not found").with_status_code(StatusCode(404)),
            };
            request.respond(response).unwrap();

            if authed_grade_hits >= 1 {
                break;
            }
        }
    });

    Mock {
        base,
        credential_posts,
        handle,
    }
}

fn client(base: &str) -> PortalClient {
    PortalClient::new(
        PortalConfig {
            sso_login_url: format!("{base}/portal2/api/identityprovider/redirect/4/login"),
            leistungen_url: format!("{base}/leistungen"),
        },
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

#[test]
fn shibboleth_login_and_grade_fetch_work_against_mock() {
    let mock = spawn_mock(Scenario::Success {
        fixture: include_str!("fixtures/meine_leistungen.html"),
    });

    let result = client(&mock.base)
        .fetch_records("uni-user", "uni-pass", None)
        .unwrap();
    assert_eq!(result.records.len(), 4);
    assert_eq!(result.records[2].get("Nummer"), "IS-201");
    assert_eq!(result.records[2].get("Bewertung"), "1,7");
    assert_eq!(mock.credential_posts.load(Ordering::SeqCst), 1);

    mock.handle.join().unwrap();
}

#[test]
fn english_locale_grade_fetch_works_against_mock() {
    let mock = spawn_mock(Scenario::Success {
        fixture: include_str!("fixtures/meine_leistungen_en.html"),
    });

    let result = client(&mock.base)
        .fetch_records("uni-user", "uni-pass", None)
        .unwrap();
    let course = result
        .records
        .iter()
        .find(|record| record.get("Nummer") == "IE 500")
        .expect("graded course row is parsed from the English page");
    assert_eq!(course.get("Titel"), "Data Management");
    assert_eq!(course.get("Bewertung"), "1.7");

    mock.handle.join().unwrap();
}

#[test]
fn idp_auth_failure_surfaces_error_text_without_retrying() {
    let mock = spawn_mock(Scenario::WrongPassword);

    let err = client(&mock.base)
        .fetch_records("uni-user", "wrong", None)
        .unwrap_err();
    assert!(matches!(err, GradeError::Auth(_)), "{err:?}");
    assert!(
        err.to_string().contains("Anmeldung fehlgeschlagen."),
        "{err}"
    );
    assert_eq!(
        mock.credential_posts.load(Ordering::SeqCst),
        1,
        "credentials are never re-submitted"
    );

    mock.handle.join().unwrap();
}

#[test]
fn saml_response_is_never_posted_to_a_foreign_host() {
    let mock = spawn_mock(Scenario::AcsOnForeignHost);

    let err = client(&mock.base)
        .fetch_records("uni-user", "uni-pass", None)
        .unwrap_err();
    assert!(matches!(err, GradeError::Auth(_)), "{err:?}");
    assert!(
        err.to_string().contains("refusing to send SAML assertion"),
        "{err}"
    );

    mock.handle.join().unwrap();
}

fn redirect(location: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(String::new())
        .with_status_code(StatusCode(302))
        .with_header(header("Location", location))
}

fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string()).with_header(header("Content-Type", "text/html"))
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}
