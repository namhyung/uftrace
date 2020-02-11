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
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pthread.h>
#include "hashmap.h"

typedef pthread_mutex_t mutex_t;
typedef struct Entry Entry;

struct Entry {
	void* key;
	hash_t hash;
	void* value;
	Entry* next;
};

struct Hashmap {
	Entry** buckets;
	size_t bucket_count;
	hash_t (*hash)(void* key);
	bool (*equals)(void* keyA, void* keyB);
	mutex_t lock;
	size_t size;
};

Hashmap* hashmap_create(size_t initial_capacity,
			hash_t (*hash)(void* key),
			bool (*equals)(void* keyA, void* keyB))
{
	assert(hash != NULL);
	assert(equals != NULL);

	Hashmap* map = malloc(sizeof(Hashmap));
	if (map == NULL) {
		return NULL;
	}

	// 0.75 load factor.
	size_t minimum_bucket_count = initial_capacity * 4 / 3;
	map->bucket_count = 1;
	while (map->bucket_count <= minimum_bucket_count) {
		// Bucket count must be power of 2.
		map->bucket_count <<= 1;
	}

	map->buckets = calloc(map->bucket_count, sizeof(Entry*));
	if (map->buckets == NULL) {
		free(map);
		return NULL;
	}

	map->size = 0;
	map->hash = hash;
	map->equals = equals;

	pthread_mutex_init(&map->lock, NULL);

	return map;
}

/**
 * Hashes the given key.
 */
static hash_t hash_key(Hashmap* map, void* key)
{
	hash_t h = map->hash(key);
	return h;
}

size_t hashmap_size(Hashmap* map)
{
	return map->size;
}

static inline size_t calculate_index(size_t bucket_count, int hash)
{
	return ((size_t) hash) & (bucket_count - 1);
}

static void expand_if_necessary(Hashmap* map)
{
	// If the load factor exceeds 0.75...
	if (map->size > (map->bucket_count * 3 / 4)) {
		// Start off with a 0.33 load factor.
		size_t new_bucket_count = map->bucket_count << 1;
		Entry** new_buckets = calloc(new_bucket_count, sizeof(Entry*));
		if (new_buckets == NULL) {
			// Abort expansion.
			return;
		}

		// Move over existing entries.
		size_t i;
		for (i = 0; i < map->bucket_count; i++) {
			Entry* entry = map->buckets[i];
			while (entry != NULL) {
				Entry* next = entry->next;
				size_t index = calculate_index(new_bucket_count, entry->hash);
				entry->next = new_buckets[index];
				new_buckets[index] = entry;
				entry = next;
			}
		}

		// Copy over internals.
		free(map->buckets);
		map->buckets = new_buckets;
		map->bucket_count = new_bucket_count;
	}
}

void hashmap_lock(Hashmap* map)
{
	pthread_mutex_lock(&map->lock);
}

void hashmap_unlock(Hashmap* map)
{
	pthread_mutex_unlock(&map->lock);
}

void hashmap_free(Hashmap* map)
{
	size_t i;

	for (i = 0; i < map->bucket_count; i++) {
		Entry* entry = map->buckets[i];
		while (entry != NULL) {
			Entry* next = entry->next;
			free(entry);
			entry = next;
		}
	}
	free(map->buckets);
	pthread_mutex_destroy(&map->lock);
	free(map);
}

hash_t hashmap_hash(void* key, size_t key_size)
{
	hash_t h = key_size;
	char* data = (char*) key;
	size_t i;

	for (i = 0; i < key_size; i++) {
		h = h * 31 + *data;
		data++;
	}
	return h;
}

static Entry* create_entry(void* key, int hash, void* value)
{
	Entry* entry = malloc(sizeof(Entry));

	if (entry == NULL) {
		return NULL;
	}
	entry->key = key;
	entry->hash = hash;
	entry->value = value;
	entry->next = NULL;
	return entry;
}

static inline bool equal_keys(void* keyA, int hashA, void* keyB, int hashB,
		bool (*equals)(void*, void*))
{
	if (keyA == keyB) {
		return true;
	}
	if (hashA != hashB) {
		return false;
	}
	return equals(keyA, keyB);
}

void* hashmap_put(Hashmap* map, void* key, void* value)
{
	hash_t hash = hash_key(map, key);
	size_t index = calculate_index(map->bucket_count, hash);

	Entry** p = &(map->buckets[index]);
	while (true) {
		Entry* current = *p;

		// Add a new entry.
		if (current == NULL) {
			*p = create_entry(key, hash, value);
			if (*p == NULL) {
				errno = ENOMEM;
				return NULL;
			}
			map->size++;
			expand_if_necessary(map);
			return NULL;
		}

		// Replace existing entry.
		if (equal_keys(current->key, current->hash, key, hash, map->equals)) {
			void* oldValue = current->value;
			current->value = value;
			return oldValue;
		}

		// Move to next entry.
		p = &current->next;
	}
}

void* hashmap_get(Hashmap* map, void* key)
{
	hash_t hash = hash_key(map, key);
	size_t index = calculate_index(map->bucket_count, hash);

	Entry* entry = map->buckets[index];
	while (entry != NULL) {
		if (equal_keys(entry->key, entry->hash, key, hash, map->equals)) {
			return entry->value;
		}
		entry = entry->next;
	}

	return NULL;
}

bool hashmap_contains_key(Hashmap* map, void* key)
{
	hash_t hash = hash_key(map, key);
	size_t index = calculate_index(map->bucket_count, hash);

	Entry* entry = map->buckets[index];
	while (entry != NULL) {
		if (equal_keys(entry->key, entry->hash, key, hash, map->equals)) {
			return true;
		}
		entry = entry->next;
	}

	return false;
}

void* hashmap_memoize(Hashmap* map, void* key,
		void* (*initial_value)(void* key, void* context),
		void* context)
{
	hash_t hash = hash_key(map, key);
	size_t index = calculate_index(map->bucket_count, hash);

	Entry** p = &(map->buckets[index]);
	while (true) {
		Entry* current = *p;

		// Add a new entry.
		if (current == NULL) {
			*p = create_entry(key, hash, NULL);
			if (*p == NULL) {
				errno = ENOMEM;
				return NULL;
			}
			void* value = initial_value(key, context);
			(*p)->value = value;
			map->size++;
			expand_if_necessary(map);
			return value;
		}

		// Return existing value.
		if (equal_keys(current->key, current->hash, key, hash, map->equals)) {
			return current->value;
		}

		// Move to next entry.
		p = &current->next;
	}
}

void* hashmap_remove(Hashmap* map, void* key)
{
	hash_t hash = hash_key(map, key);
	size_t index = calculate_index(map->bucket_count, hash);

	// Pointer to the current entry.
	Entry** p = &(map->buckets[index]);
	Entry* current;
	while ((current = *p) != NULL) {
		if (equal_keys(current->key, current->hash, key, hash, map->equals)) {
			void* value = current->value;
			*p = current->next;
			free(current);
			map->size--;
			return value;
		}

		p = &current->next;
	}

	return NULL;
}

void hashmap_for_each(Hashmap* map,
		      bool (*callback)(void* key, void* value, void* context),
		      void* context)
{
	size_t i;
	for (i = 0; i < map->bucket_count; i++) {
		Entry* entry = map->buckets[i];
		while (entry != NULL) {
			Entry *next = entry->next;
			if (!callback(entry->key, entry->value, context)) {
				return;
			}
			entry = next;
		}
	}
}

size_t hashmap_current_capacity(Hashmap* map)
{
	size_t bucket_count = map->bucket_count;
	return bucket_count * 3 / 4;
}

size_t hashmap_count_collisions(Hashmap* map)
{
	size_t collisions = 0;
	size_t i;
	for (i = 0; i < map->bucket_count; i++) {
		Entry* entry = map->buckets[i];
		while (entry != NULL) {
			if (entry->next != NULL) {
				collisions++;
			}
			entry = entry->next;
		}
	}
	return collisions;
}

hash_t hashmap_default_hash(void* key)
{
	return *((hash_t*) key);
}

bool hashmap_default_equals(void *keyA, void *keyB)
{
	hash_t a = *((hash_t *)keyA);
	hash_t b = *((hash_t *)keyB);
	return a == b;
}
