//! The catalogue bundled into the Worker at build time (see `build.rs`).

use foiled_core::catalogue::CatalogueEntry;

static BUNDLE: &str = include_str!(concat!(env!("OUT_DIR"), "/catalogue.json"));

#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    entries: Vec<CatalogueEntry>,
}

impl Catalogue {
    /// The entries merged into `catalogue/entries/` when this build was made.
    /// `foiled-lint` has already validated them in CI, so a parse failure
    /// here is a build bug and panics at start-up rather than serving a
    /// partial catalogue.
    pub fn bundled() -> Self {
        let entries: Vec<CatalogueEntry> =
            serde_json::from_str(BUNDLE).expect("bundled catalogue parses");
        Catalogue { entries }
    }

    pub fn from_entries(mut entries: Vec<CatalogueEntry>) -> Self {
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Catalogue { entries }
    }

    pub fn entries(&self) -> &[CatalogueEntry] {
        &self.entries
    }

    pub fn get(&self, id: &str) -> Option<&CatalogueEntry> {
        self.entries.iter().find(|e| e.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_contains_the_repository_entries() {
        let c = Catalogue::bundled();
        assert!(c.get("foiled/demo-app/1.0.0").is_some());
        assert!(c.get("emulator/redis/7.0").is_some());
        let ids: Vec<&str> = c.entries().iter().map(|e| e.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}
