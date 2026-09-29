//! Fake for the [`BlocksIndex`] port: scripted search results, a record of
//! every query. Never talks to a network.

use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::ports::blocks::{BlockEntry, BlockQuery, BlocksIndex, BlocksIndexError};

/// A [`BlocksIndex`] whose search results you script per test.
///
/// The fake answers every query with the one scripted result — the entry
/// list, or the error. Every query is recorded, so tests can assert what was
/// asked, not just what came back.
///
/// ```
/// use ks_core::ports::blocks::{BlockEntry, BlockQuery, BlocksIndex};
/// use ks_testing::{block_on, blocks::FakeBlocksIndex};
///
/// let index = FakeBlocksIndex::with_entries(vec![BlockEntry {
///     name: "acme/rollout".to_string(),
///     publisher: ks_core::ports::supply_chain::SignerIdentity::Key {
///         key_id: "2026-q3".to_string(),
///     },
///     readme: String::new(),
///     versions: Vec::new(),
/// }]);
/// let query = BlockQuery { text: "rollout".to_string(), limit: 20 };
/// let found = block_on(index.search(&query)).expect("the scripted entries");
/// assert_eq!(found.len(), 1);
/// assert_eq!(index.queries(), vec![query]);
/// ```
pub struct FakeBlocksIndex {
    result: Result<Vec<BlockEntry>, BlocksIndexError>,
    queries: Mutex<Vec<BlockQuery>>,
}

impl FakeBlocksIndex {
    /// Creates a fake that answers every query with `entries`.
    pub fn with_entries(entries: Vec<BlockEntry>) -> FakeBlocksIndex {
        FakeBlocksIndex { result: Ok(entries), queries: Mutex::new(Vec::new()) }
    }

    /// Creates a fake that fails every query with `error`.
    pub fn with_error(error: BlocksIndexError) -> FakeBlocksIndex {
        FakeBlocksIndex { result: Err(error), queries: Mutex::new(Vec::new()) }
    }

    /// Every query the fake was asked, oldest first.
    pub fn queries(&self) -> Vec<BlockQuery> {
        self.queries.lock().expect("fake blocks index query record").clone()
    }
}

impl BlocksIndex for FakeBlocksIndex {
    fn search<'a>(
        &'a self,
        query: &'a BlockQuery,
    ) -> BoxFuture<'a, Result<Vec<BlockEntry>, BlocksIndexError>> {
        self.queries.lock().expect("fake blocks index query record").push(query.clone());
        Box::pin(std::future::ready(self.result.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use ks_core::ports::supply_chain::SignerIdentity;

    fn entry(name: &str) -> BlockEntry {
        BlockEntry {
            name: name.to_string(),
            publisher: SignerIdentity::Key { key_id: "k".to_string() },
            readme: String::new(),
            versions: Vec::new(),
        }
    }

    fn query(text: &str) -> BlockQuery {
        BlockQuery { text: text.to_string(), limit: 20 }
    }

    #[test]
    fn scripts_the_same_entries_for_every_query() {
        let index = FakeBlocksIndex::with_entries(vec![entry("acme/one"), entry("acme/two")]);
        for _ in 0..2 {
            let found = block_on(index.search(&query("one"))).expect("scripted entries");
            assert_eq!(found.len(), 2);
        }
        assert_eq!(index.queries(), vec![query("one"), query("one")]);
    }

    #[test]
    fn scripts_errors_and_records_the_query_anyway() {
        let index =
            FakeBlocksIndex::with_error(BlocksIndexError::Backend { message: "down".to_string() });
        assert_eq!(
            block_on(index.search(&query("x"))),
            Err(BlocksIndexError::Backend { message: "down".to_string() })
        );
        assert_eq!(index.queries().len(), 1);
    }

    #[test]
    fn an_empty_script_is_a_normal_empty_answer() {
        let index = FakeBlocksIndex::with_entries(Vec::new());
        assert_eq!(block_on(index.search(&query("nothing"))), Ok(Vec::new()));
    }
}
