#include "hashmap.h"

#include <assert.h>

unsigned long hashmap_hash2(char *str) {

	unsigned long hash = 5381;
	int c;

	while (c = *str++){
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}


	return hash;

}

int hashmap_hash(char *key, size_t len) {
	int hash, i;
	for (hash = i = 0; i < len; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

int hashmap_get_hash(char *key, int hMapSize) {
	return hashmap_hash2(key) % hMapSize;
}

entry *hashmap_get_entry_by_key(char *key, map *hmap) {

	int hash = hashmap_get_hash(key, hmap->size);

	entry *entryItem = hmap->table[hash];

	while (entryItem != NULL) {
		if (entryItem->key == key) {
			return entryItem;
		}
		entryItem = entryItem->nextInChain;

	}
	return entryItem;
}

int hashmap_insert_entry(char *key, void *data, map *hmap) {
	entry *newEntry;
	newEntry = (entry*) malloc(sizeof(newEntry));

	newEntry->key = key;
	newEntry->data = data;

	int hash = hashmap_get_hash(key, hmap->size);

	if (!newEntry) {
		return -1;
	}

	newEntry->nextInChain = hmap->table[hash];
	hmap->table[hash] = newEntry;

	return 0;
}

int testHash(char *key, int hMapSize) {
	int hash = hashmap_get_hash(key, hMapSize);
	if (hash <= hMapSize) {
		return 0;
	}
	return -1;
}

int testInsert(map *hmap) {

	char *key1 = "12345678";
	char *data1 = "newData";

	int hash = hashmap_get_hash(key1, hmap->size);

	assert(hashmap_insert_entry(key1, data1, hmap) == 0);

	assert(hashmap_get_entry_by_key(key1, hmap) != NULL);

	assert(hashmap_insert_entry(key1, data1, hmap) == 0);

	assert(
			(hmap->table[hash]->key == key1)
					&& (hmap->table[hash]->nextInChain->key == key1));
	return 0;
}

int testEdit(map *hmap, char *key) {

	char *newData = "newData";

	entry *toEdit = hashmap_get_entry_by_key(key, hmap);

	toEdit->data = newData;

	assert(strcmp(toEdit->data, "newData") == 0);

	return 0;
}

map *hashmap_createMap(int mapSize) {
	map *newMap = (map*) malloc(sizeof(map));
	newMap->size = mapSize;
	newMap->table = calloc(mapSize, sizeof(entry));
	assert(newMap->table != NULL);
	return newMap;
}
