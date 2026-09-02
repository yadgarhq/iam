//! `iam` — the identity module's logic service.
//!
//! **It holds no store, and that absence is the design (D4).** There is no sqlx
//! and no `yadgar-store` in this crate's dependency tree: a logic service reaches
//! its data only over the `-db` API, which is what makes the twin a connection
//! concentrator rather than merely a boundary. N replicas of this service with
//! embedded pools would multiply connections against an engine with hard limits.

#![forbid(unsafe_code)]

/// What `main` decides before it connects to anything, here rather than there so
/// a test can reach it — `main` is a binary entry point and nothing in it is.
pub mod boot;
pub mod crypto;
pub mod invalidate;
/// What this process does when the certificate it read at boot is replaced
/// underneath it. [`serve`] reads those files once; this notices they changed.
pub mod rotate;
/// The certificate this service PRESENTS; [`upstream`] is how it VERIFIES the
/// one `iam-db` presents. Two directions, one word.
pub mod serve;
pub mod service;
pub mod upstream;

/// Generated from the vendored contract (D16, D70). The module tree mirrors the
/// protobuf package path — generated cross-package references are emitted as
/// `super::super::common::v1::Meta`, so a flattened tree fails to compile.
pub mod pb {
    pub mod yadgar {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("yadgar.common.v1");
            }
        }
        pub mod iam {
            pub mod v1 {
                tonic::include_proto!("yadgar.iam.v1");
            }
        }
        pub mod iamdb {
            pub mod v1 {
                tonic::include_proto!("yadgar.iamdb.v1");
            }
        }
    }
}
