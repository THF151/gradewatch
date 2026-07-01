use std::process::Command;

use base64::{Engine, engine::general_purpose::STANDARD};
use tempfile::tempdir;

#[test]
fn gen_master_key_prints_32_byte_base64() {
    let output = Command::new(env!("CARGO_BIN_EXE_gradewatch"))
        .arg("--gen-master-key")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let key = STANDARD.decode(stdout.trim()).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn hash_password_prints_argon2_hash() {
    let output = Command::new(env!("CARGO_BIN_EXE_gradewatch"))
        .args(["--hash-password", "admin-secret"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("$argon2"));
}

#[test]
fn hash_password_b64_prints_base64_encoded_argon2_hash() {
    let output = Command::new(env!("CARGO_BIN_EXE_gradewatch"))
        .args(["--hash-password-b64", "admin-secret"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let decoded = String::from_utf8(STANDARD.decode(stdout.trim()).unwrap()).unwrap();
    assert!(decoded.starts_with("$argon2"));
}

#[test]
fn healthcheck_initializes_database_and_returns_ok() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("gradewatch.db");
    let output = Command::new(env!("CARGO_BIN_EXE_gradewatch"))
        .arg("--healthcheck")
        .env("MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .env(
            "ADMIN_PASSWORD_HASH",
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$7w8aC9+oCw1+zfl+t2KJwAfWT8v12bJeLKA3Heg96iQ",
        )
        .env("DATA_DIR", dir.path())
        .env("DATABASE_PATH", &db_path)
        .env("LOG_LEVEL", "error")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "ok");
    assert!(db_path.exists());
}
