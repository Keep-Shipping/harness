//! The Keep Shipping engine: DAG planner and executor, run state, and policy
//! gates.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod blocks;
pub mod cache;
pub mod credentials;
pub mod decide;
pub mod denial;
pub mod deploy_verify;
pub mod exec;
pub mod gsc_sitemap_submit;
pub mod journal;
pub mod k8s_rollout;
pub mod oci_artifact;
pub mod oci_image;
pub mod oci_verify;
pub mod plan;
pub mod plan_guard;
pub mod policy_gate;
pub mod rollback;
pub mod run;
pub mod sched;
pub mod secrets;
pub mod signing;
pub mod state;
pub mod steps;
pub mod tofu_apply;
pub mod tofu_plan;
pub mod vm_deploy;
