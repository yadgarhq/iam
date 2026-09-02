//! What `main` decides before it connects to anything — in a place a test can
//! reach.
//!
//! `main` is a binary entry point, so nothing in it is reachable from a test.
//! That is fine for wiring and not fine for decisions. The broker credential is
//! exactly the kind that is not: every outcome of getting it wrong is a boot
//! that either stops or connects ANONYMOUSLY, and the second one looks healthy.
//! `iam-db` grew a `boot` module for the same reason and this is its twin.

use crate::invalidate::Credentials;

/// The file holding the broker password. A PATH, never the value (D80).
const PASSWORD_FILE_KEY: &str = "NATS_PASSWORD_FILE";

/// The account that password belongs to.
const USER_KEY: &str = "NATS_USER";

/// What this service presents to the broker, or `None` if it presents nothing.
///
/// A PATH rather than a value (D80), the same shape `YADGAR_KEYS_DIR` and
/// `ENROLMENT_CA_PEM_FILE` already use, and for the same reason twice over: a
/// deployment that is not the reference one assembles the Secret by hand, and a
/// password in an environment variable is a password in `kubectl describe pod`.
///
/// **Every way of being half-configured is a boot failure**, and there are four:
/// a path that cannot be read, a file that is empty, a password with no user to
/// go with it, and a user with no password. All four describe a deployment that
/// asked for authentication and cannot perform it, and the only alternative to
/// refusing is connecting anonymously — which succeeds, looks healthy, and leaves
/// D72's invalidation events publishable by anything on the pod network.
///
/// **THE FOURTH ARM IS THE ONE THAT WAS MISSING, and it is the asymmetry that
/// made the other three worth less than they read.** A password with no user
/// refused; a user with no password returned `Ok(None)` and connected
/// anonymously with a warning. The chart never produces that state — its
/// `NATS_USER` and `NATS_PASSWORD_FILE` are rendered together inside one
/// `{{- if .Values.nats.passwordSecret }}`, so clearing the Secret drops both and
/// an adopter whose broker asks for nothing is unaffected. A deployment
/// assembled by hand has no such guard, and D80's whole premise is that such
/// deployments exist.
///
/// Takes the environment as a lookup rather than reading it directly, so a test
/// can state a whole environment without mutating the process — `std::env` is
/// global and `cargo test` runs threads in parallel.
pub fn nats_credentials(
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<Credentials>, BootError> {
    // AN UNSET KEY AND AN EMPTY ONE ARE THE SAME DEPLOYMENT. A chart that renders
    // a variable with no value must not be a different configuration from one
    // that omits it, so both collapse to the empty string here and every arm
    // below tests emptiness rather than presence.
    let user = env(USER_KEY).unwrap_or_default();
    let path = env(PASSWORD_FILE_KEY).unwrap_or_default();

    if path.is_empty() {
        return match user.is_empty() {
            // NEITHER, which is how a deployment says the broker asks for none.
            true => Ok(None),
            false => Err(BootError::NatsUserWithoutPassword),
        };
    }

    let raw =
        std::fs::read_to_string(&path).map_err(|source| BootError::NatsPasswordUnreadable {
            path: path.clone(),
            source,
        })?;
    // TRAILING NEWLINE ONLY. `kubectl create secret --from-file` of a file a
    // person edited keeps the newline their editor added, and a password with a
    // `\n` on the end is a different password — rejected by a broker configured
    // from the same 1Password item, as an authorization violation nobody can see.
    // Inner whitespace is a legitimate part of a password and is left alone.
    let password = raw.trim_end_matches(['\n', '\r']).to_string();
    if password.is_empty() {
        return Err(BootError::NatsPasswordEmpty { path });
    }
    if user.is_empty() {
        return Err(BootError::NatsPasswordWithoutUser);
    }
    Ok(Some(Credentials { user, password }))
}

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error(
        "{PASSWORD_FILE_KEY} names {path}, which cannot be read: {source}. It is the password \
         iam presents to the broker (D22) for D72's cache invalidation. Refusing to start rather \
         than connecting to the broker without one."
    )]
    NatsPasswordUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{PASSWORD_FILE_KEY} names {path}, which is empty. A blank password is not one. \
         Either put the broker's password in that file or unset the variable, which is how \
         a deployment says the broker asks for none."
    )]
    NatsPasswordEmpty { path: String },

    #[error(
        "{PASSWORD_FILE_KEY} is set and {USER_KEY} is not. The broker's authorization block \
         names an account and a password together, so a password with no user cannot \
         authenticate against it. Set both, or neither."
    )]
    NatsPasswordWithoutUser,

    #[error(
        "{USER_KEY} is set and {PASSWORD_FILE_KEY} is not. The broker's authorization block \
         names an account and a password together, so a named account with no password cannot \
         authenticate against it — and connecting anonymously instead is the silent fall back \
         this refusal exists to remove. Set both, or neither."
    )]
    NatsUserWithoutPassword,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment stating only what a test cares about.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// A file holding exactly these bytes, at a path this test owns.
    fn password_file(name: &str, contents: &str) -> String {
        let dir = std::env::temp_dir().join(format!("yadgar-iam-boot-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the password directory");
        let path = dir.join("password");
        std::fs::write(&path, contents).expect("write the password");
        path.to_str().expect("a utf-8 path").to_string()
    }

    /// Deliberately unlike anything the implementation could contain. A fixture
    /// equal to a constant in the code under test would pass for a build that
    /// used its own idea of a password rather than the configured one.
    const PASSWORD: &str = "sentinel-of-the-nats-password-4c17";
    const USER: &str = "sentinel-user";

    #[test]
    fn both_set_is_the_credential_the_files_and_the_environment_describe() {
        let path = password_file("both", PASSWORD);
        let got = nats_credentials(env_of(&[
            ("NATS_PASSWORD_FILE", path.as_str()),
            ("NATS_USER", USER),
        ]))
        .expect("a fully configured broker credential loads")
        .expect("and it is a credential rather than nothing");

        assert_eq!(got.user, USER);
        assert_eq!(got.password, PASSWORD);
    }

    #[test]
    fn neither_set_presents_nothing_rather_than_refusing() {
        // A BROKER WITH NO AUTHORIZATION BLOCK IS A SUPPORTED DEPLOYMENT, and
        // the chart says so. Refusing here would turn every deployment that has
        // not cut over into a CrashLoopBackOff.
        assert!(nats_credentials(env_of(&[]))
            .expect("an unconfigured broker is not an error")
            .is_none());
    }

    #[test]
    fn a_password_with_no_user_refuses_the_boot() {
        let path = password_file("no-user", PASSWORD);
        let err = nats_credentials(env_of(&[("NATS_PASSWORD_FILE", path.as_str())]))
            .expect_err("a password with no account to present it as cannot authenticate");

        assert!(matches!(err, BootError::NatsPasswordWithoutUser), "{err}");
    }

    #[test]
    fn a_user_with_no_password_refuses_the_boot_rather_than_connecting_anonymously() {
        // THE ASYMMETRY THIS CLOSES. The opposite half-configuration refused from
        // the day it was written; this one returned `Ok(None)` and connected with
        // no credential at all, logging a warning nobody reads — the silent fall
        // back the sibling arm's own message calls out.
        //
        // MUTATION THIS CATCHES: returning `Ok(None)` when the path is empty
        // regardless of the user, which is what the code did. Every other test in
        // this file passes under it, including the one above — the two arms are
        // independent and only this one sees the missing half.
        let err = nats_credentials(env_of(&[("NATS_USER", USER)]))
            .expect_err("an account with no password cannot authenticate");

        assert!(matches!(err, BootError::NatsUserWithoutPassword), "{err}");
    }

    #[test]
    fn an_empty_password_file_refuses_the_boot() {
        // A blank password is not one, and a Secret whose key exists and holds
        // nothing is a deployment mistake rather than a request to connect
        // anonymously.
        let path = password_file("empty", "\n");
        let err = nats_credentials(env_of(&[
            ("NATS_PASSWORD_FILE", path.as_str()),
            ("NATS_USER", USER),
        ]))
        .expect_err("a blank password must refuse the boot");

        assert!(matches!(err, BootError::NatsPasswordEmpty { .. }), "{err}");
    }

    #[test]
    fn an_unreadable_password_file_refuses_the_boot_naming_the_path() {
        // NAMING THE PATH IS THE POINT. An optional volume mount that cannot be
        // satisfied mounts an EMPTY directory rather than failing the pod, so the
        // only evidence the operator gets is this message.
        let err = nats_credentials(env_of(&[
            ("NATS_PASSWORD_FILE", "/var/run/secrets/nats/absent"),
            ("NATS_USER", USER),
        ]))
        .expect_err("a path naming no file must refuse the boot");

        assert!(
            matches!(err, BootError::NatsPasswordUnreadable { .. }),
            "{err}"
        );
        assert!(
            err.to_string().contains("/var/run/secrets/nats/absent"),
            "the refusal must name the path it could not read: {err}"
        );
    }

    #[test]
    fn only_the_trailing_newline_is_stripped() {
        // `kubectl create secret --from-file` stores the bytes exactly, editor
        // newline included, and a password with a `\n` on the end is a different
        // password. Inner whitespace is a legitimate part of one and is left
        // alone — stripping it would send a different password than the Secret
        // holds, failing as an authorization violation with no visible cause.
        let path = password_file("newline", "  spaced  password  \r\n");
        let got = nats_credentials(env_of(&[
            ("NATS_PASSWORD_FILE", path.as_str()),
            ("NATS_USER", USER),
        ]))
        .expect("it loads")
        .expect("and it is a credential");

        assert_eq!(got.password, "  spaced  password  ");
    }

    #[test]
    fn an_empty_password_file_variable_is_the_same_as_an_absent_one() {
        // A chart that renders the key with no value must not be a different
        // deployment from one that omits it.
        assert!(nats_credentials(env_of(&[("NATS_PASSWORD_FILE", "")]))
            .expect("an empty path is no path")
            .is_none());
    }
}
