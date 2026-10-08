//! One line of prose per built-in step kind, for hover.
//!
//! The catalog itself carries schemas, not documentation, and
//! `docs/STEPS.md` is generated from it; the wording here mirrors that
//! document and `docs/LANGUAGE.md`. A kind nobody has written a line for
//! still hovers — just without the sentence.

/// What a built-in step kind does, in one line.
pub fn kind_doc(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "oci.image" => "Build a container image from a Dockerfile, and publish its digest and tag.",
        "oci.artifact" => {
            "Push files as an OCI artifact by digest, optionally attached to an image and signed."
        }
        "oci.verify" => {
            "Refuse to continue unless an image digest carries a signature from a named identity."
        }
        "tofu.plan" => "Plan an infrastructure change, and count what it would add and destroy.",
        "terraform.plan" => {
            "Plan an infrastructure change with Terraform, and count what it would add and destroy."
        }
        "vm.deploy" => {
            "Deploy to a fleet of hosts over SSH, one batch at a time, with a pinned host key per host."
        }
        "approval" => "Hold the run until a human answers, showing an earlier step's outputs.",
        "tofu.apply" => {
            "Apply exactly the plan file an approval was bound to. Yields `applied` and the root outputs as `out.<name>`."
        }
        "terraform.apply" => {
            "Apply exactly the Terraform plan file an approval was bound to. Yields `applied` and the root outputs as `out.<name>`."
        }
        "k8s.rollout" => {
            "Roll a deployment out to a cluster. Its outputs are known only at run time."
        }
        "decide" => {
            "Ask a model a question, and branch on the answer it declares in `returns:`. Also \
             yields `confidence`, `probabilities` and a `reason` the engine wrote from the plan."
        }
        _ => return None,
    })
}

/// What a step does: its kind's line, or a note that the kind is not
/// built in and so unchecked.
pub fn step_doc(kind: Option<&str>) -> String {
    match kind {
        Some(kind) => match kind_doc(kind) {
            Some(doc) => format!("`{kind}` — {doc}"),
            None => {
                format!("`{kind}` — not a built-in kind, so its inputs and outputs are unchecked.")
            }
        },
        None => "this step declares no kind, so its inputs and outputs are unchecked.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::Catalog;

    #[test]
    fn every_built_in_kind_has_a_line() {
        for kind in Catalog::builtin().kinds() {
            assert!(kind_doc(&kind.name).is_some(), "no doc for `{}`", kind.name);
        }
    }

    #[test]
    fn an_unknown_kind_says_so_instead_of_nothing() {
        assert_eq!(kind_doc("acme.deploy"), None);
        assert!(step_doc(Some("acme.deploy")).contains("not a built-in kind"));
        assert!(step_doc(None).contains("declares no kind"));
    }
}
