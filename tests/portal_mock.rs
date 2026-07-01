use std::{thread, time::Duration};

use gradewatch::error::GradeError;
use gradewatch::{config::PortalConfig, portal::fetch::PortalClient};
use tiny_http::{Header, Method, Response, Server, StatusCode};

#[test]
fn cas_login_redirect_and_grade_fetch_work_against_mock() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let base = format!("http://{addr}");

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

            if method == Method::Get && path.starts_with("/leistungen") {
                if cookie.contains("portal_session=ok") {
                    authed_grade_hits += 1;
                    request
                        .respond(html_response(include_str!(
                            "fixtures/meine_leistungen.html"
                        )))
                        .unwrap();
                } else {
                    request
                        .respond(
                            html_response("<html>not logged in</html>")
                                .with_status_code(StatusCode(403)),
                        )
                        .unwrap();
                }
            } else if method == Method::Get && path.starts_with("/cas/login") {
                let body = r#"
                    <form action="/cas/login">
                      <input name="execution" value="e1s1">
                      <input name="_eventId" value="submit">
                    </form>
                "#;
                request.respond(html_response(body)).unwrap();
            } else if method == Method::Post && path == "/cas/login" {
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                assert!(body.contains("username=uni-user"));
                assert!(body.contains("password=uni-pass"));
                request
                    .respond(
                        Response::empty(StatusCode(302))
                            .with_header(header("Location", "/service?ticket=ST-1")),
                    )
                    .unwrap();
            } else if method == Method::Get && path.starts_with("/service") {
                request
                    .respond(
                        Response::empty(StatusCode(302))
                            .with_header(header("Location", "/leistungen"))
                            .with_header(header("Set-Cookie", "portal_session=ok; Path=/")),
                    )
                    .unwrap();
            } else {
                request
                    .respond(Response::from_string("not found").with_status_code(StatusCode(404)))
                    .unwrap();
            }

            if authed_grade_hits >= 2 {
                break;
            }
        }
    });

    let client = PortalClient::new(
        PortalConfig {
            cas_login_url: format!("{base}/cas/login"),
            service_url: format!("{base}/service"),
            leistungen_url: format!("{base}/leistungen"),
        },
        Duration::from_secs(2),
        Duration::from_secs(2),
    );

    let result = client.fetch_records("uni-user", "uni-pass", None).unwrap();
    assert_eq!(result.records.len(), 4);
    assert_eq!(result.records[2].get("Nummer"), "IS-201");
    assert_eq!(result.records[2].get("Bewertung"), "1,7");

    handle.join().unwrap();
}

#[test]
fn cas_auth_failure_surfaces_error_text() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let base = format!("http://{addr}");

    let handle = thread::spawn(move || {
        while let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(2)) {
            let path = request.url().to_string();
            let method = request.method().clone();
            if method == Method::Get && path.starts_with("/leistungen") {
                request
                    .respond(html_response("<html>not logged in</html>"))
                    .unwrap();
            } else if method == Method::Get && path.starts_with("/cas/login") {
                request
                    .respond(html_response(
                        r#"<form action="/cas/login"><input name="execution" value="e1s1"></form>"#,
                    ))
                    .unwrap();
            } else if method == Method::Post && path == "/cas/login" {
                request
                    .respond(html_response(
                        r#"<div role="alert">Invalid credentials</div>"#,
                    ))
                    .unwrap();
                break;
            } else {
                request
                    .respond(Response::from_string("not found").with_status_code(StatusCode(404)))
                    .unwrap();
            }
        }
    });

    let client = PortalClient::new(
        PortalConfig {
            cas_login_url: format!("{base}/cas/login"),
            service_url: format!("{base}/service"),
            leistungen_url: format!("{base}/leistungen"),
        },
        Duration::from_secs(2),
        Duration::from_secs(2),
    );

    let err = client.fetch_records("uni-user", "wrong", None).unwrap_err();
    assert!(matches!(err, GradeError::Auth(_)));
    assert!(err.to_string().contains("Invalid credentials"));
    handle.join().unwrap();
}

fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string()).with_header(header("Content-Type", "text/html"))
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}
