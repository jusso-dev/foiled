//! Golden test for write-up lint and public pages (#35). Each
//! `testdata/write-ups/examples/*.json` (validated against
//! `schemas/write-up.schema.json`) is linted into
//! `testdata/write-ups/lint/<name>.json`. Examples with no lint errors are
//! turned into public pages in `testdata/public/pages/` and listed in
//! `testdata/public/lists/all.json` (both schema-checked by the repository
//! lint). Every body's Markdown tree is in `testdata/write-ups/markdown/`.
//!
//! To regenerate after an intended change, run with FOILED_BLESS=1 and
//! review the diff.

use std::path::{Path, PathBuf};

use foiled_core::writeup::{
    LintContext, PageFacts, WriteUp, has_errors, lint, page_leaks, public_page,
};

fn root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata")).to_path_buf()
}

fn golden(path: PathBuf, value: &impl serde::Serialize) {
    let got = serde_json::to_string_pretty(value).unwrap() + "\n";
    if std::env::var("FOILED_BLESS").is_ok() {
        std::fs::write(&path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{} missing; run with FOILED_BLESS=1", path.display()));
    assert_eq!(got, want, "{} differs", path.display());
}

#[test]
fn lint_markdown_and_pages_match_goldens() {
    let mut names: Vec<String> = std::fs::read_dir(root().join("write-ups/examples"))
        .unwrap()
        .map(|e| {
            e.unwrap()
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    let mut pages = Vec::new();
    for name in &names {
        let w: WriteUp = serde_json::from_str(
            &std::fs::read_to_string(root().join(format!("write-ups/examples/{name}.json")))
                .unwrap(),
        )
        .unwrap();
        let ctx = LintContext {
            tenant_ids: vec![w.tenant_id.clone()],
            confirmed: Default::default(),
        };
        let findings = lint(&w, &ctx);
        golden(
            root().join(format!("write-ups/lint/{name}.json")),
            &findings,
        );
        golden(
            root().join(format!("write-ups/markdown/{name}.json")),
            &foiled_core::markdown::parse(&w.body_md),
        );
        if has_errors(&findings) {
            continue;
        }
        let mut facts = PageFacts::default();
        facts
            .advisories
            .insert("FOILED-DEMO-0001".into(), 1_792_022_400_000);
        let page = public_page(&w, &facts, 1_792_200_000_000);
        assert!(!page_leaks(&page, &ctx.tenant_ids), "{name}");
        golden(root().join(format!("public/pages/{name}.json")), &page);
        pages.push(page.summary_row());
    }
    assert_eq!(pages.len(), 1, "only the clean example publishes");
    golden(
        root().join("public/lists/all.json"),
        &serde_json::json!({ "items": pages }),
    );
}

#[test]
fn hostile_example_fails_the_rules_it_should() {
    let raw = std::fs::read_to_string(root().join("write-ups/lint/hostile-markdown.json")).unwrap();
    for rule in ["raw-html", "unsafe-link", "exploit-code"] {
        assert!(raw.contains(&format!("\"{rule}\"")), "{rule}");
    }
    let leak = std::fs::read_to_string(root().join("write-ups/lint/tenant-leak.json")).unwrap();
    for rule in [
        "tenant-data",
        "ip-address",
        "personal-information",
        "actor-wording",
        "confirmed-without-analyst",
        "assessed-wording",
        "placeholder",
        "sources",
    ] {
        assert!(leak.contains(&format!("\"{rule}\"")), "{rule}");
    }
    let tree =
        std::fs::read_to_string(root().join("write-ups/markdown/hostile-markdown.json")).unwrap();
    assert!(!tree.contains("javascript:"));
    assert!(!tree.contains("data:text"));
    assert!(!tree.contains("\"//evil"));
    assert!(tree.contains("\\\\u{202e}"), "bidi made visible");
}
