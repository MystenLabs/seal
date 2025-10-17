// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use moka::policy::EvictionPolicy;
use moka::sync::Cache;
use std::hash::Hash;
use std::time::Duration;

pub(crate) const DEFAULT_SIZE: u64 = 1000;
pub(crate) const DEFAULT_TTL_IN_MILLIS: u64 = 60 * 60 * 1000; // 1 hour

/// Creates a new thread-safe LRU cache with the specified TTL and size.
pub(crate) fn lru_cache<K: Hash + Eq + Send + Sync + 'static, V: Clone + Send + Sync + 'static>(
    ttl: u64,
    size: u64,
) -> Cache<K, V> {
    Cache::builder()
        .time_to_live(Duration::from_millis(ttl))
        .eviction_policy(EvictionPolicy::lru())
        .max_capacity(size)
        .build()
}

/// Creates a default LRU cache with default values for TTL, [DEFAULT_TTL_IN_MILLIS], and size, [DEFAULT_SIZE].
pub(crate) fn default_lru_cache<
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
>() -> Cache<K, V> {
    lru_cache(DEFAULT_TTL_IN_MILLIS, DEFAULT_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = lru_cache(1000, 10);
        cache.insert(1, "value1");
        assert_eq!(cache.get(&1), Some("value1"));
    }

    #[test]
    fn test_cache_expiry() {
        let cache = lru_cache(1000, 10);
        cache.insert(1, "value1");
        sleep(Duration::from_millis(1100));
        assert_eq!(cache.get(&1), None);
    }

    #[test]
    fn test_cache_overwrite() {
        let cache = lru_cache(1000, 10);
        cache.insert(1, "value1");
        cache.insert(1, "value2");
        assert_eq!(cache.get(&1), Some("value2"));
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = lru_cache(1000, 2);
        cache.insert(1, "value1");
        cache.insert(2, "value2");
        cache.insert(3, "value3");

        // Moka runs maintenance tasks lazily, so to force the eviction of the excess entry we need to force it to run pending tasks
        cache.run_pending_tasks();

        assert_eq!(cache.get(&1), None); // Should be evicted
        assert_eq!(cache.get(&2), Some("value2"));
        assert_eq!(cache.get(&3), Some("value3"));
    }
}
