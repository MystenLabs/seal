// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::time::current_epoch_time;
use lru::LruCache;
use parking_lot::Mutex;
use std::hash::Hash;
use std::num::NonZero;

pub(crate) const CACHE_SIZE: usize = 1000;
pub(crate) const CACHE_TTL: u64 = 60 * 60 * 1000; // 1 hour

// Generic LRU cache with TTL

struct CacheEntry<V> {
    pub value: V,
    pub expiry: u64,
}

pub(crate) struct Cache<K, V> {
    ttl: u64,
    cache: Mutex<LruCache<K, CacheEntry<V>>>,
}

impl<K: Hash + Eq, V: Copy> Cache<K, V> {
    /// Create a new cache with a given TTL and size.
    /// Panics if ttl or size is 0.
    pub fn new(ttl: u64, size: usize) -> Self {
        assert!(size > 0 && ttl > 0, "TTL and size must be greater than 0");
        Self {
            ttl,
            cache: Mutex::new(LruCache::new(NonZero::new(size).expect("fixed value"))),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.lock();
        match cache.get(key) {
            Some(entry) => {
                if entry.expiry < current_epoch_time() {
                    cache.pop(key);
                    None
                } else {
                    Some(entry.value)
                }
            }
            None => None,
        }
    }

    pub fn insert(&self, key: K, value: V) {
        let mut cache = self.cache.lock();
        cache.put(
            key,
            CacheEntry {
                value,
                expiry: current_epoch_time() + self.ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = Cache::new(1000, 10);
        cache.insert(1, "value1");
        assert_eq!(cache.get(&1), Some("value1"));
    }

    #[test]
    fn test_cache_expiry() {
        let cache = Cache::new(1000, 10);
        cache.insert(1, "value1");
        sleep(Duration::from_millis(1100));
        assert_eq!(cache.get(&1), None);
    }

    #[test]
    fn test_cache_overwrite() {
        let cache = Cache::new(1000, 10);
        cache.insert(1, "value1");
        cache.insert(1, "value2");
        assert_eq!(cache.get(&1), Some("value2"));
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = Cache::new(1000, 2);
        cache.insert(1, "value1");
        cache.insert(2, "value2");
        cache.insert(3, "value3");
        assert_eq!(cache.get(&1), None); // Should be evicted
        assert_eq!(cache.get(&2), Some("value2"));
        assert_eq!(cache.get(&3), Some("value3"));
    }
}
