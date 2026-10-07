//! What an operator reads when the boot refuses (ledger 1258).
//!
//! `main` used to return `Result<(), Box<dyn Error>>`, and Rust prints a `main`
//! that returns `Err` with DEBUG. A bare `?` on a typed error — `Keys::from_env`
//! is the first one `run` can reach — arrived as its variant name,
//! `Unconfigured`; a refusal already converted to its sentence arrived as a
//! quoted, escaped string: `Error: "LISTEN is not a host:port address: …"`,
//! every inner quote a `\"`. `main` now calls `run()` and prints `Error: {e}`
//! with Display. The unit tests in `src/` prove the sentences exist; only
//! running the BINARY proves they reach the operator as written.
//!
//! **The exit code is not what these tests discriminate.** An `Err` from
//! `main` exits 1 and so does `ExitCode::FAILURE`, so reverting to
//! `-> Result` turns the Display assertion red and leaves the exit code alone.

mod support;

use std::process::Command;

use support::{cleartext_env, fresh_keys_dir, run_to_exit, BIN};

/// The `Error: ` line from a refused boot, held to plain Display.
fn refusal_line(status: std::process::ExitStatus, stderr: &str) -> String {
    assert!(
        !status.success(),
        "a refused boot must exit non-zero: {status:?}"
    );
    let line = stderr
        .lines()
        .rfind(|l| l.starts_with("Error: "))
        .unwrap_or_else(|| panic!("no `Error: ` line on stderr: {stderr}"))
        .to_string();
    assert!(
        !line.starts_with("Error: \"") && !line.contains("\\\""),
        "the refusal was printed as a Debug string: {line}"
    );
    line
}

/// Run the binary directly, for refusals that come before `shared.yaml` is
/// read and so need no mount namespace.
fn refusal_without_mounts(vars: &[(&str, String)]) -> String {
    let out = Command::new(BIN)
        .env_clear()
        .envs(vars.iter().map(|(k, v)| (*k, v.as_str())))
        .output()
        .expect("the test rig could not start the binary");
    refusal_line(out.status, &String::from_utf8_lossy(&out.stderr))
}

/// A TYPED error: `KeyError::Unconfigured`, reached by a bare `?` — `run`'s
/// FIRST typed refusal, and reached before `boot::listener` needs any file
/// since TLS is unconfigured. Debug of the error would print `Unconfigured`,
/// the bare variant name with nothing an operator can act on.
#[test]
fn a_typed_refusal_is_printed_as_its_sentence() {
    let line = refusal_without_mounts(&[]);
    assert!(
        line.contains("YADGAR_KEYS_DIR is not set"),
        "the refusal must name the variable: {line}"
    );
    assert!(
        !line.contains("Unconfigured"),
        "the operator got the Debug variant name, not the sentence: {line}"
    );
}

/// A bare parse, named on the way out: `IAM_DB_PORT` is read before the shared
/// document, so this also needs no mount namespace.
#[test]
fn an_unparsable_db_port_names_the_variable() {
    let keys_dir = fresh_keys_dir();
    let mut vars = cleartext_env(&keys_dir);
    vars.retain(|(k, _)| *k != "IAM_DB_PORT");
    vars.push(("IAM_DB_PORT", "abc".to_string()));
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("IAM_DB_PORT is not a port number"),
        "the refusal must name the variable: {line}"
    );
}

/// `LISTEN` is parsed after the shared document is read and the rotation
/// schedule is resolved, so this boot needs the document mounted to get that
/// far.
#[test]
fn an_unparsable_listen_names_the_variable() {
    let keys_dir = fresh_keys_dir();
    let mut vars = cleartext_env(&keys_dir);
    vars.retain(|(k, _)| *k != "LISTEN");
    vars.push(("LISTEN", "notanaddr".to_string()));
    let (status, stderr) = run_to_exit(&vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains("LISTEN is not a host:port address"),
        "the refusal must name the variable: {line}"
    );
    assert!(
        !line.contains("AddrParseError"),
        "the operator got the Debug of the parse error: {line}"
    );
}
