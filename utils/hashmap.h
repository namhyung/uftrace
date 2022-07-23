/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HASHMAP_H
#define __HASHMAP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__amd64__) || defined(__aarch64__)
#define ARCH64
#else
#define ARCH32
#endif

#if defined(ARCH64)
typedef int64_t hash_t;
typedef uint64_t uhash_t;
#elif defined(ARCH32)
typedef int32_t hash_t;
typedef uint32_t uhash_t;
#endif

/** A hash map. */
typedef struct Hashmap Hashmap;

/**
 * Creates a new hash map. Returns NULL if memory allocation fails.
 *
 * @param initialCapacity number of expected entries
 * @param hash function which hashes keys
 * @param equals function which compares keys for equality
 */
Hashmap *hashmap_create(size_t initialCapacity, hash_t (*hash)(void *key),
			bool (*equals)(void *keyA, void *keyB));

/**
 * Frees the hash map. Does not free the keys or values themselves.
 */
void hashmap_free(Hashmap *map);

/**
 * Hashes the memory pointed to by key with the given size. Useful for
 * implementing hash functions.
 */
hash_t hashmap_hash(void *key, size_t keySize);

/**
 * Puts value for the given key in the map. Returns pre-existing value if
 * any, otherwise it returns the given value.
 *
 * If memory allocation fails, this function returns NULL, the map's size
 * does not increase, and errno is set to ENOMEM.
 */
void *hashmap_put(Hashmap *map, void *key, void *value);

/**
 * Gets a value from the map. Returns NULL if no entry for the given key is
 * found or if the value itself is NULL.
 */
void *hashmap_get(Hashmap *map, void *key);

/**
 * Returns true if the map contains an entry for the given key.
 */
bool hashmap_contains_key(Hashmap *map, void *key);

/**
 * Gets the value for a key. If a value is not found, this function gets a
 * value and creates an entry using the given callback.
 *
 * If memory allocation fails, the callback is not called, this function
 * returns NULL, and errno is set to ENOMEM.
 */
void *hashmap_memoize(Hashmap *map, void *key, void *(*initialValue)(void *key, void *context),
		      void *context);

/**
 * Removes an entry from the map. Returns the removed value or NULL if no
 * entry was present.
 */
void *hashmap_remove(Hashmap *map, void *key);

/**
 * Gets the number of entries in this map.
 */
size_t hashmap_size(Hashmap *map);

/**
 * Invokes the given callback on each entry in the map. Stops iterating if
 * the callback returns false.
 */
void hashmap_for_each(Hashmap *map, bool (*callback)(void *key, void *value, void *context),
		      void *context);

/**
 * Concurrency support.
 */

/**
 * Locks the hash map so only the current thread can access it.
 */
void hashmap_lock(Hashmap *map);

/**
 * Unlocks the hash map so other threads can access it.
 */
void hashmap_unlock(Hashmap *map);

/**
 * Key utilities.
 */
hash_t hashmap_default_hash(void *key);

/**
 * Compares two keys for equality.
 */
bool hashmap_default_equals(void *keyA, void *keyB);

/**
 * Gets current capacity.
 */
size_t hashmap_current_capacity(Hashmap *map);

/**
 * Counts the number of entry collisions.
 */
size_t hashmap_count_collisions(Hashmap *map);

/**
 * Key utilities - use pointer as key.
 */
hash_t hashmap_ptr_hash(void *key);

/**
 * Compares two pointers for equality.
 */
bool hashmap_ptr_equals(void *keyA, void *keyB);

#endif /* __HASHMAP_H */
