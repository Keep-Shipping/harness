//! Which changes to a block's interface break a consumer, one case each, plus
//! the ordering and the type comparison the rest of #83 leans on.
//!
//! Every case states the answer twice where it can: the [`Change`] that was
//! produced *and* whether it is breaking, because a diff that silently
//! classifies a breaking change as fine is worse than no diff.

use ks_core::block_diff::{Change, Usage, diff};
use ks_core::ports::block_source::{BlockDefinition, BlockField};

fn field(name: &str, type_name: &str, required: bool) -> BlockField {
    BlockField { name: name.to_string(), type_name: type_name.to_string(), required }
}

fn definition(inputs: &[BlockField], outputs: &[BlockField]) -> BlockDefinition {
    BlockDefinition {
        summary: "Builds and ships a web service.".into(),
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
    }
}

fn empty() -> BlockDefinition {
    definition(&[], &[])
}

#[test]
fn an_input_that_is_gone_is_breaking() {
    let old = definition(&[field("image", "string", true)], &[]);
    let new = empty();
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::InputRemoved { name: "image".into() }]);
    assert!(d.is_breaking());
}

#[test]
fn a_new_required_input_is_breaking() {
    let old = empty();
    let new = definition(&[field("region", "string", true)], &[]);
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::InputAdded { name: "region".into(), required: true }]);
    assert!(d.is_breaking());
}

#[test]
fn a_new_optional_input_is_not_breaking() {
    let old = empty();
    let new = definition(&[field("region", "string", false)], &[]);
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::InputAdded { name: "region".into(), required: false }]);
    assert!(!d.is_breaking(), "a consumer that never supplies `region` still works");
}

#[test]
fn an_input_that_goes_optional_to_required_is_breaking() {
    let old = definition(&[field("region", "string", false)], &[]);
    let new = definition(&[field("region", "string", true)], &[]);
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::InputRequired { name: "region".into() }]);
    assert!(d.is_breaking(), "a consumer that omitted `region` no longer type-checks");
}

#[test]
fn an_input_that_goes_required_to_optional_is_not_breaking() {
    let old = definition(&[field("region", "string", true)], &[]);
    let new = definition(&[field("region", "string", false)], &[]);
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::InputOptional { name: "region".into() }]);
    assert!(!d.is_breaking(), "a consumer that already supplies `region` still works");
}

#[test]
fn an_input_whose_type_changed_is_breaking() {
    let old = definition(&[field("replicas", "int", true)], &[]);
    let new = definition(&[field("replicas", "string", true)], &[]);
    let d = diff(&old, &new);
    assert_eq!(
        d.changes(),
        [Change::InputRetyped { name: "replicas".into(), from: "int".into(), to: "string".into() }]
    );
    assert!(d.is_breaking());
}

#[test]
fn an_output_that_is_gone_is_breaking() {
    let old = definition(&[], &[field("url", "string", false)]);
    let new = empty();
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::OutputRemoved { name: "url".into() }]);
    assert!(d.is_breaking());
}

#[test]
fn a_new_output_is_not_breaking() {
    let old = empty();
    let new = definition(&[], &[field("url", "string", false)]);
    let d = diff(&old, &new);
    assert_eq!(d.changes(), [Change::OutputAdded { name: "url".into() }]);
    assert!(!d.is_breaking(), "nothing was reading an output that did not exist");
}

/// A respelling that is only whitespace is the same type: reporting it would
/// make every block that reformats its annotations look like a breaking
/// release.
#[test]
fn a_whitespace_only_respell_of_a_type_is_no_change() {
    let old = definition(&[field("image", "list[string]", true)], &[]);
    let new = definition(&[field("image", "  list[ string ]  ", true)], &[]);
    assert!(diff(&old, &new).is_empty());

    // The same for a name this crate cannot parse at all: compared as text.
    let old = definition(&[], &[field("url", "weird type", false)]);
    let new = definition(&[], &[field("url", "  weird type ", false)]);
    assert!(diff(&old, &new).is_empty());
}

#[test]
fn identical_definitions_are_an_empty_diff() {
    let old = definition(
        &[field("image", "string", true), field("region", "string", false)],
        &[field("url", "url", false)],
    );
    let d = diff(&old, &old.clone());
    assert!(d.is_empty());
}

/// Inputs before outputs, removals in the old order and additions in the new
/// one — the order a diagnostic prints them in has to be a function of the two
/// definitions, not of a hash map.
#[test]
fn a_mixed_diff_comes_out_in_a_deterministic_order() {
    let old = definition(
        &[field("image", "string", true), field("replicas", "int", true)],
        &[field("url", "string", false)],
    );
    let new = definition(
        &[field("replicas", "string", true), field("region", "string", true)],
        &[field("host", "string", false)],
    );
    let d = diff(&old, &new);
    assert_eq!(
        d.changes(),
        [
            Change::InputRemoved { name: "image".into() },
            Change::InputRetyped {
                name: "replicas".into(),
                from: "int".into(),
                to: "string".into()
            },
            Change::InputAdded { name: "region".into(), required: true },
            Change::OutputRemoved { name: "url".into() },
            Change::OutputAdded { name: "host".into() },
        ]
    );
    assert!(d.is_breaking(), "the removed input alone is enough");
}

/// The name-level gate: `blocks upgrade` refuses on what `affecting` returns
/// and allows the upgrade when it returns nothing, even if the diff is
/// breaking. Every rule gets a hit and a miss where both make sense, because a
/// gate that only ever fires is indistinguishable from a gate that always does.
#[test]
fn affecting_hits_only_what_the_site_actually_uses() {
    // A removed input hits the site that supplies it...
    let removed = diff(&definition(&[field("replicas", "int", true)], &[]), &definition(&[], &[]));
    assert_eq!(removed.affecting(&Usage::new(&["replicas"], &[])).count(), 1);
    assert!(
        removed.affecting(&Usage::new(&["image"], &[])).next().is_none(),
        "`image` is what the site supplies"
    );

    // ...and a new required input hits the site that does *not* supply it,
    // because the site has nothing to put in a field it never mentioned.
    let added = diff(&empty(), &definition(&[field("region", "string", true)], &[]));
    assert_eq!(added.affecting(&Usage::new(&[], &[])).count(), 1);
    assert!(
        added.affecting(&Usage::new(&["region"], &[])).next().is_none(),
        "the site already supplies `region`, so the old definition merely let it"
    );

    // An input that became required is the same asymmetry under another name.
    let now_required = diff(
        &definition(&[field("region", "string", false)], &[]),
        &definition(&[field("region", "string", true)], &[]),
    );
    assert_eq!(now_required.affecting(&Usage::new(&["image"], &[])).count(), 1);
    assert!(now_required.affecting(&Usage::new(&["region"], &[])).next().is_none());

    // A retyped input hits the site that supplies it and spares the one that
    // does not — the value-level half of this is `check`'s job, so the names
    // are the whole of it here.
    let retyped_input = diff(
        &definition(&[field("replicas", "int", true)], &[]),
        &definition(&[field("replicas", "string", true)], &[]),
    );
    assert_eq!(retyped_input.affecting(&Usage::new(&["replicas"], &[])).count(), 1);
    assert!(retyped_input.affecting(&Usage::new(&["image"], &[])).next().is_none());

    // Outputs are the same rule against the reads rather than the supplies.
    let retyped_output = diff(
        &definition(&[], &[field("url", "string", false)]),
        &definition(&[], &[field("url", "url", false)]),
    );
    assert_eq!(retyped_output.affecting(&Usage::new(&[], &["url"])).count(), 1);
    assert!(retyped_output.affecting(&Usage::new(&[], &["host"])).next().is_none());
    let removed_output = diff(&definition(&[], &[field("url", "string", false)]), &empty());
    assert_eq!(removed_output.affecting(&Usage::new(&[], &["url"])).count(), 1);
    assert!(removed_output.affecting(&Usage::new(&[], &["host"])).next().is_none());
}

#[test]
fn a_breaking_diff_an_unaffected_site_never_sees_is_allowable() {
    // Everything here breaks *some* consumer; this site touches none of it, so
    // the upgrade is allowed. A gate that also refused here would refuse every
    // release of every block. Note the site supplies `region` — a newly
    // required input is no trouble for a site that already fills it.
    let old = definition(
        &[field("region", "string", false), field("image", "string", true)],
        &[field("url", "string", false)],
    );
    let new = definition(
        &[field("region", "string", true), field("image", "string", true)],
        &[field("id", "url", false)],
    );
    let d = diff(&old, &new);
    assert!(d.is_breaking(), "`region` becoming required and `url` going away break a consumer");
    let site = Usage::new(&["region"], &["digest"]);
    assert!(d.affecting(&site).next().is_none());
    // ...while a site that omits `region`, or reads the removed `url`, is not.
    assert_eq!(d.affecting(&Usage::new(&["env"], &["digest"])).count(), 1);
    assert_eq!(d.affecting(&Usage::new(&["region"], &["url"])).count(), 1);
}

#[test]
fn changes_display_as_a_short_sentence() {
    let old = definition(&[field("replicas", "int", true)], &[field("url", "string", false)]);
    let new = definition(&[field("region", "string", true)], &[field("id", "url", false)]);
    assert_eq!(diff(&old, &new).changes()[0].to_string(), "input `replicas` was removed");
    assert_eq!(diff(&old, &new).changes()[2].to_string(), "output `url` was removed");

    let added = Change::InputAdded { name: "region".into(), required: true };
    assert_eq!(added.to_string(), "input `region` is new and required");
    assert!(added.is_breaking());

    let retyped =
        Change::OutputRetyped { name: "url".into(), from: "String".into(), to: "Url".into() };
    assert_eq!(retyped.to_string(), "output `url` changed type from String to Url");
    assert_eq!(
        Change::InputOptional { name: "region".into() }.to_string(),
        "input `region` is now optional"
    );
}
