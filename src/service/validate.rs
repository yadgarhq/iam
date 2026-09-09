//! The bounds this boundary enforces on every request that carries a
//! field, and the checks that apply them.
//!
//! ONE FILE FOR THE SHARED FIELDS ONLY. A bound argued for ONE request
//! lives with that request — `MAX_PASSWORD_BYTES` beside
//! `validate_redemption`, `MAX_EXPIRES_IN_SECONDS` beside
//! `check_issue_credential` — because ADR-0565 requires the argument to be
//! re-made per field and a shared file is where a shared judgement hides.
//! The three here are genuinely shared: a label, an idempotency key and an
//! entity id are the same field wherever they appear.

use super::*;

/// The longest `label` accepted, IN CHARACTERS, because that is what stores it.
///
/// A BOUND AND NOT A REQUIREMENT: an EMPTY label is accepted, because the
/// contract says this field is `LoginRequest.label` exactly and `Login` requires
/// nothing of it. Refusing an empty one here would be a refusal a caller written
/// against `Login` newly meets.
///
/// **255 AND NOT 256, AND CHARACTERS AND NOT BYTES.** This was
/// `MAX_LABEL_BYTES = 256`, tested with `>`, and it was wrong twice over. The
/// column is `label VARCHAR(255)` on `CHARSET=utf8mb4`
/// (`iam-db/src/schema.rs`), and `VARCHAR(n)` in utf8mb4 bounds CHARACTERS.
/// Measured against `mariadb:11.8.9` — the image `iam-db`'s README stands up —
/// with that column declared exactly as the schema declares it, at the stock
/// `sql_mode` (`STRICT_TRANS_TABLES,…`):
///
/// | label                     | characters | bytes | outcome                                        |
/// | ------------------------- | ---------- | ----- | ---------------------------------------------- |
/// | 255 × `l`                 | 255        | 255   | stored                                         |
/// | 256 × `l`                 | 256        | 256   | `ERROR 1406 Data too long for column 'label'`  |
/// | 255 × `U+1F600`           | 255        | 1020  | stored                                         |
/// | 256 × `U+1F600`           | 256        | 1024  | `ERROR 1406 Data too long for column 'label'`  |
/// | 100 × `U+1F600`           | 100        | 400   | stored                                         |
///
/// So the old bound was wrong in BOTH directions. It ADMITTED a 256-byte ASCII
/// label the column refuses — and because `iam-db` renders every engine error as
/// `UNAVAILABLE "storage unavailable"`, that refusal reached the caller as an
/// outage of a database that was working. It also REFUSED a 100-character emoji
/// label the column stores without complaint.
///
/// **THE NUMBER IS THE COLUMN'S AND THAT COUPLING IS DELIBERATE**, which is the
/// one way this differs from [`MAX_EXPIRES_IN_SECONDS`] above. That bound is a
/// judgement about what a field MEANS, and it deliberately refuses to import a
/// storage ceiling that moved between engine minor versions. A `VARCHAR` width
/// does not move on its own: it is a declaration in a migration, and changing it
/// is a migration somebody writes. The alternatives to naming it here are worse
/// — leaving the lockout, or accepting a silent truncation under a `sql_mode`
/// nothing asserts (the same INSERTs above store a CLIPPED 255-character label
/// and report success under `sql_mode = ''`). Refusing here makes the outcome
/// this service's own, and independent of a `sql_mode` it neither sets nor
/// checks. If the column widens, this constant is what has to move with it.
const MAX_LABEL_CHARS: usize = 255;

/// The longest `Idempotency.key` accepted, IN CHARACTERS, because that is what
/// the two ledgers that store one are declared in.
///
/// **THE NUMBER IS THE COLUMN'S**, the same coupling [`MAX_LABEL_CHARS`] argues
/// for and against the same alternative. `iam_enrolment_redemption` and
/// `iam_inherited_setting_write` both declare `idempotency_key VARCHAR(255) NOT
/// NULL PRIMARY KEY` on `CHARSET=utf8mb4` (`iam-db/src/schema.rs`), and
/// `VARCHAR(n)` in utf8mb4 bounds CHARACTERS. Measured against `mariadb:11.8.9`
/// — the image `iam-db`'s README stands up — with the column exactly as the
/// schema declares it, at the stock `sql_mode` (`STRICT_TRANS_TABLES,…`):
///
/// | key             | characters | bytes | outcome                                                  |
/// | --------------- | ---------- | ----- | -------------------------------------------------------- |
/// | 255 × `k`       | 255        | 255   | stored                                                   |
/// | 256 × `k`       | 256        | 256   | `ERROR 1406 Data too long for column 'idempotency_key'`  |
/// | 255 × `U+1F600` | 255        | 1020  | stored, as a `PRIMARY KEY`                               |
/// | 256 × `U+1F600` | 256        | 1024  | `ERROR 1406 Data too long for column 'idempotency_key'`  |
///
/// **ONE CONSTANT FOR TWO FIELDS, AND IT IS A DERIVATION RATHER THAN A SHARED
/// JUDGEMENT.** ADR-0565 requires a bound to be re-argued per field; the
/// argument here comes out identical twice because it is not an opinion about
/// what a key MEANS. Two columns, one declared width, one unit. The derivation
/// has no per-field term in it, exactly as [`MAX_ENCRYPTED_FIELD_BYTES`] has
/// none. If either column widens, this constant is what has to move with it.
///
/// **THE SWEEP, BECAUSE FIXING AN INSTANCE IS NOT CLOSING A CLASS — AND THE
/// SWEEP IS WHY THIS IS CHECKED ON TWO RPCs AND NOT ON TEN.** TEN messages on
/// `yadgar.iam.v1` carry an `Idempotency`, and they fall in four groups:
///
/// - **TWO hand the key to a store that PERSISTS it** —
///   [`IamService::redeem_enrolment`] and [`IamService::set_inherited_setting`].
///   `iam-db` reads `r.idempotency` on exactly those two handlers, and those two
///   ledgers are the only columns in that schema a caller's key reaches. They
///   are what this bound is for.
/// - **FIVE forward a key `iam-db` then DISCARDS** — `CreateUser`,
///   `IssueEnrolment`, `AddTeamMember`, `RemoveTeamMember` and
///   `RevokeCredential`. No column receives one, so a bound here would be a
///   refusal the store does not make.
/// - **ONE forwards no key at all**, deliberately:
///   [`IamService::issue_credential`] sets `idempotency: None` on the hop, and
///   the comment there carries ADR-0519's argument for that silence.
/// - **TWO reach no store** — `SetUserAdmin` and `SetRateLimitOverride` answer
///   `UNIMPLEMENTED` before anything is forwarded.
///
/// **THE SECOND GROUP IS A COUPLING TO ANOTHER MODULE'S PRESENT BEHAVIOUR, and
/// it is stated rather than left to be discovered: the five discarded keys are a
/// D9 defect of their own, and whoever gives one of them a ledger must extend
/// this check to that RPC in the same change.** They will not find this comment
/// by grepping for the column they add.
///
/// **A BOUND AND NOT A REQUIREMENT.** An EMPTY key still means "no
/// deduplication" wherever the contract allows one — `set_inherited_setting`
/// skips the ledger entirely on an empty key. `RedeemEnrolment` requires a
/// non-empty one, and that requirement is its own and predates this bound; see
/// [`validate_redemption`].
const MAX_IDEMPOTENCY_KEY_CHARS: usize = 255;

/// The longest caller-supplied ENTITY ID accepted, IN CHARACTERS: the width of
/// the `VARCHAR(96)` columns this schema keys its rows on.
///
/// **NAMED FOR THE WIDTH'S MEANING RATHER THAN FOR "AN ID", BECAUSE THIS SCHEMA
/// HAS TWO ID WIDTHS AND 96 IS THE WRONG ANSWER FOR ONE OF THEM.** The 96-wide
/// columns hold a `yadgar:<kind>:<uuid7>` primary key or a foreign key to one —
/// `iam_user.id`, `iam_team.id`, `iam_credential.user_id`,
/// `iam_enrolment.user_id`, `iam_team_member.{team_id,user_id}`,
/// `iam_team_setting_override.team_id`, `iam_inherited_setting_write.team_id`.
/// The ACTOR columns beside them are `VARCHAR(64)` —
/// `iam_user.{created_by,updated_by,owner_user_id,team_id}`,
/// `iam_team.{created_by,updated_by}`, `iam_team_member.added_by` — and none is
/// in this class: every one is written as the literal `'system'` by `iam-db` or
/// is never written at all. **A future caller-supplied value landing in a
/// 64-wide column needs its own constant, not this one.**
///
/// Measured against `mariadb:11.8.9` at the stock `sql_mode`, with the columns
/// exactly as `iam-db/src/schema.rs` declares them:
///
/// | id             | characters | bytes | outcome                                          |
/// | -------------- | ---------- | ----- | ------------------------------------------------ |
/// | 96 × `u`       | 96         | 96    | stored                                           |
/// | 97 × `u`       | 97         | 97    | `ERROR 1406 Data too long for column 'user_id'`  |
/// | 96 × `U+1F600` | 96         | 384   | stored                                           |
///
/// CHARACTERS for [`MAX_LABEL_CHARS`]'s reason and counted as `char`s for its
/// reason too: a Rust `char` is a Unicode scalar and utf8mb4 stores one per
/// character, so the two counts agree exactly.
///
/// **ONE CONSTANT FOR TWO FIELDS, ON [`MAX_IDEMPOTENCY_KEY_CHARS`]'s ARGUMENT.**
/// `IssueCredentialRequest.user_id` and `SetInheritedSettingRequest.team_id` are
/// two names for one shape — an identifier this schema minted, in a column of
/// one declared width — so the derivation has no per-field term.
///
/// **THE SWEEP.** FIVE implemented RPCs hand a caller-supplied id to a statement
/// `iam-db` runs, and only these TWO hand one to a column UNGUARDED. The other
/// three each already answer without an engine error:
///
/// - `IssueEnrolment.user_id` is consulted through `live_user` before any write,
///   so an over-long one is `NOT_FOUND` and never meets a column.
/// - `AddTeamMember` reaches `INSERT IGNORE`, and the row is skipped — but by
///   the FOREIGN KEY, not by `IGNORE`. Both measured on mariadb 11.8:
///   `INSERT IGNORE` downgrades `1406` to warning `1265`, and separately
///   downgrades the resulting FK violation `1452` to a warning too, so nothing
///   lands and the engine refuses nothing. Against a table with NO foreign key
///   the same statement reports `rows_affected 1` and STORES the value
///   TRUNCATED to the column width. So this exclusion rests on `fk_t`/`fk_u`
///   existing: delete them and the failure mode becomes silent truncation of a
///   caller-supplied primary key, at which point this bound has to come back.
/// - `RemoveTeamMember` reaches a `DELETE`, which matches nothing and refuses
///   nothing.
///
/// A bound on the last two would refuse what the store accepts. Three further
/// RPCs are outside the sweep rather than inside it and passing:
/// `RevokeCredential.credential_id` reaches a `WHERE` clause and never a column,
/// and `SetUserAdmin` and `SetRateLimitOverride` answer `UNIMPLEMENTED` before
/// any store call.
///
/// **WHAT THIS DOES NOT CLOSE, SAID PLAINLY.** `iam-db`'s `create_credential` is
/// the one write in that service with NO liveness check, so a user id that is
/// SHORT but names nobody still fails the foreign key and still returns
/// `UNAVAILABLE`. This constant refuses exactly what the COLUMN refuses and no
/// more; the remaining half is a `live_user` call in `iam-db` and is filed
/// rather than reached from here.
const MAX_ENTITY_ID_CHARS: usize = 96;

/// The ONE bound on a caller-supplied `label`, shared by the three RPCs that
/// store one.
///
/// **ONE FUNCTION FOR THREE FIELDS, AND THAT IS NOT THE SHORTCUT IT LOOKS
/// LIKE.** ADR-0565 says a bound is re-argued per field rather than shared —
/// but that is about the NUMBER, and `LoginRequest.label`,
/// `RedeemEnrolmentRequest.label` and `IssueCredentialRequest.label` are the
/// same field, described in `iam.proto` as the same free text, travelling to
/// `iam-db` as the same `CreateCredentialRequest.label`, and landing in the same
/// column. Three copies of one number is how two of them end up stale.
///
/// **THE SWEEP, BECAUSE FIXING AN INSTANCE IS NOT CLOSING A CLASS.**
/// `iam.proto` carries exactly three caller-supplied labels and every one is
/// checked here. `Credential.label` on `ListCredentials` is a READ of a stored
/// value and not an input. `iam` builds no other `CreateCredentialRequest`.
///
/// **CHARACTERS COUNTED AS `char`s, WHICH IS THE COLUMN'S OWN UNIT.** A Rust
/// `char` is a Unicode scalar value and utf8mb4 stores one per character, so the
/// two counts agree exactly. Graphemes would NOT: a flag or a family emoji is
/// several scalar values and one grapheme, so counting graphemes under-counts
/// against the column and re-opens the refusal this exists to prevent — and it
/// would need a crate to do it.
pub(super) fn check_label(label: &str) -> Result<(), Status> {
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(Status::invalid_argument(
            "the label is longer than the store will hold: at most 255 \
             characters, counted as characters and not as bytes",
        ));
    }
    Ok(())
}

/// The ONE bound on a caller-supplied idempotency key, shared by the two RPCs
/// whose keys are STORED.
///
/// One function for the same reason [`check_label`] is one: the two fields are
/// the same field — `yadgar.common.v1.Idempotency.key`, described once, landing
/// in two columns of one declared width. The membership argument, and the
/// coupling it rests on, are on [`MAX_IDEMPOTENCY_KEY_CHARS`].
pub(super) fn check_idempotency_key(key: &str) -> Result<(), Status> {
    if key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS {
        return Err(Status::invalid_argument(
            "the idempotency key is longer than the store will hold: at most \
             255 characters, counted as characters and not as bytes",
        ));
    }
    Ok(())
}

/// The ONE bound on a caller-supplied entity id, shared by the two RPCs that
/// hand one to a column unguarded.
///
/// The field is NAMED in the refusal, as ADR-0565 requires and as
/// [`check_stored_names`] already does: two fields share this message, and one
/// that named neither would send an operator to check both.
pub(super) fn check_entity_id(field: &str, id: &str) -> Result<(), Status> {
    if id.chars().count() > MAX_ENTITY_ID_CHARS {
        return Err(Status::invalid_argument(format!(
            "`{field}` is longer than any identifier this store holds: at most \
             96 characters, counted as characters and not as bytes"
        )));
    }
    Ok(())
}
