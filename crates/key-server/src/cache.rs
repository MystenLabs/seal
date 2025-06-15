// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use lru::LruCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::num::NonZero;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct CacheOptions {
    /// The maximum number of entries in the MVR cache.
    pub max_entries_mvr: usize,
    /// The maximum number of entries in the package cache.
    pub max_entries_package: usize,
}

impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            max_entries_mvr: 10_000,
            max_entries_package: 10_000,
        }
    }
}

pub(crate) struct Cache<K, V> {
    inner: Mutex<LruCache<K, V>>,
}

impl<K: Hash + Eq, V: Copy> Cache<K, V> {
    /// Create a new cache with a given size.
    ///
    /// # Panics
    ///
    /// Panics if size is 0.
    pub fn new(size: usize) -> Self {
        let Some(size) = NonZero::new(size) else {
            panic!("size must be greater than 0");
        };
        Self {
            inner: Mutex::new(LruCache::new(size)),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.inner.lock();
        cache.get(key).copied()
    }

    pub fn insert(&self, key: K, value: V) {
        let mut cache = self.inner.lock();
        cache.put(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = Cache::new(1000);
        cache.insert(1, "value1");
        assert_eq!(cache.get(&1), Some("value1"));
    }

    #[test]
    fn test_cache_overwrite() {
        let cache = Cache::new(1000);
        cache.insert(1, "value1");
        cache.insert(1, "value2");
        assert_eq!(cache.get(&1), Some("value2"));
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = Cache::new(2);
        cache.insert(1, "value1");
        cache.insert(2, "value2");
        cache.insert(3, "value3");
        assert_eq!(cache.get(&1), None); // Should be evicted
        assert_eq!(cache.get(&2), Some("value2"));
        assert_eq!(cache.get(&3), Some("value3"));
    }
}
