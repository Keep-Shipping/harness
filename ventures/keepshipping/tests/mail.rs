//! The waitlist mail as this venture sends it: rendered through
//! [`keepshipping_waitlist::templates`] (the themed templates
//! `src/lib.rs` mounts) with fixed sample data, snapshotted as HTML and
//! plain text, plus a round-trip of the theme JSON itself.

use cratefield_core::{Brand, Rendered};
use cratefield_mail_templates::MailTheme;
use cratefield_module_waitlist::{ConfirmMailData, ConfirmedMailData};
use keepshipping_waitlist::{mail_theme, templates};
use serde_json::json;

fn render(id: &str, data: &serde_json::Value) -> Rendered {
    templates()
        .into_iter()
        .find(|(template_id, _)| template_id == id)
        .unwrap_or_else(|| panic!("{id} registered"))
        .1
        .render(data, "en")
        .expect("renders")
}

fn confirm_data() -> serde_json::Value {
    json!(ConfirmMailData {
        venture: "keepshipping".to_owned(),
        product: "keepshipping".to_owned(),
        email: "ada@example.com".to_owned(),
        confirm_url:
            "https://api.keepshipping.run/v1/waitlist/confirm?token=01J9ZQ4M8K2D7X3B6N5R0T1V2W"
                .to_owned(),
        brand: Brand::default(),
    })
}

fn confirmed_data() -> serde_json::Value {
    json!(ConfirmedMailData {
        venture: "keepshipping".to_owned(),
        product: "keepshipping".to_owned(),
        email: "ada@example.com".to_owned(),
        position: 42,
        status_url:
            "https://api.keepshipping.run/v1/waitlist/status?token=01J9ZQ4M8K2D7X3B6N5R0T1V2W"
                .to_owned(),
        brand: Brand::default(),
    })
}

#[test]
fn confirm_mail_snapshots() {
    let rendered = render("waitlist/confirm", &confirm_data());
    insta::assert_snapshot!("confirm_html", rendered.html);
    insta::assert_snapshot!("confirm_text", rendered.text);
}

#[test]
fn confirmed_mail_snapshots() {
    let rendered = render("waitlist/confirmed", &confirmed_data());
    insta::assert_snapshot!("confirmed_html", rendered.html);
    insta::assert_snapshot!("confirmed_text", rendered.text);
}

#[test]
fn the_composed_theme_is_the_keep_shipping_theme() {
    let theme = mail_theme();
    assert_eq!(theme.brand_name, "Keep Shipping");
    assert_eq!(theme.wordmark, "Keep Shipping");
    assert_eq!(theme.site_url, "https://keepshipping.run");
    assert_eq!(theme.contact.as_deref(), Some("contact@keepshipping.run"));
    assert_eq!(
        theme.logo_url.as_deref(),
        Some("https://keepshipping.run/assets/email/logo-64.png")
    );
    assert_eq!((theme.logo_width, theme.logo_height), (32, 32));
    assert_eq!((theme.radius, theme.button_radius), (0, 0));
    assert_eq!(theme.light.accent, "#1950cc");
    assert_eq!(theme.light.button, "#1950cc");
    assert_eq!(theme.dark.bg, "#11161f");
    assert!(theme.font.contains("Bricolage Grotesque"), "{}", theme.font);
    assert!(theme.mono.contains("DM Mono"), "{}", theme.mono);
}

#[test]
fn the_theme_file_round_trips() {
    let raw = include_str!("../src/mail-theme.json");
    let parsed = MailTheme::from_json(raw).expect("mail-theme.json is valid JSON");
    assert_eq!(parsed, mail_theme(), "the shipped theme is the file's theme");
    let reserialized = serde_json::to_string(&parsed).expect("serialises");
    assert_eq!(MailTheme::from_json(&reserialized).expect("re-parses"), parsed);
}

/// The mail carries a "Sent with Owlpost" footer only when Owlpost actually
/// sends the mail — that is, only when Owlpost is in the venture's Factory
/// Zero registry entry. Today it is the transport and nothing more, so the
/// registry entry comes first (no such use), and the confirm and confirmed
/// bodies carry no footer either. Adding the footer before adding the entry
/// would be claiming a sender the product is not built with.
#[test]
fn no_owlpost_footer_while_owlpost_is_not_a_registry_entry() {
    let venture = ks_core::built_with::venture();
    for entry in &venture.uses {
        let said = format!("{} ({})", entry.name, entry.id);
        assert!(
            !entry.id.to_lowercase().contains("owlpost")
                && !entry.name.to_lowercase().contains("owlpost"),
            "Owlpost is in the registry entry now ({said}); if it also sends the \
             mail, a 'Sent with Owlpost' footer is honest — add it and update this test"
        );
    }
    for (name, rendered) in [
        ("confirm", render("waitlist/confirm", &confirm_data())),
        ("confirmed", render("waitlist/confirmed", &confirmed_data())),
    ] {
        for (part, body) in [("html", &rendered.html), ("text", &rendered.text)] {
            assert!(
                !body.to_lowercase().contains("sent with owlpost"),
                "the {name} {part} body claims an Owlpost footer: {body}"
            );
        }
    }
}
