/*
 * hashmap.h
 *
 *  Created on: 27 Feb 2016
 *      Author: root
 */

#ifndef HASHMAP_H_
#define HASHMAP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bucketItem{
    char *key;
    void *data;
    struct bucketItem *nextInChain;
}entry;

typedef struct hashMap{
    entry **table;
    int size;
}map;

//main functionality
int hashmap_hash(char *key, size_t len);
int hashmap_get_hash(char *key, int hMapSize);
entry *hashmap_get_entry_by_key(char *key, map *hmap);
int hashmap_insert_entry(char *key, void *data, map *hmap);
map *hashmap_createMap(int mapSize);




#endif /* HASHMAP_H_ */
