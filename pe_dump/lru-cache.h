/*
 *   This is an implementation of a O(1) LRU cache.
 *   Copyright (C) 2010  Roberto Perdisci (perdisci@cs.uga.edu)
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LRUC_TTL 5*60 // 5 minutes

typedef unsigned int u_int;

typedef struct ht_entry {

    const char *key;
    struct lruc_entry *le;
    struct ht_entry *next;

} ht_entry_t;

typedef struct hash_table {

    u_int length;
    ht_entry_t **vect;

} hash_table_t;

typedef struct lruc_entry {

    char *key;
    void *value;
    time_t time;
    struct lruc_entry *prev;
    struct lruc_entry *next;

} lruc_entry_t;

typedef struct lru_cache {

    hash_table_t *ht;  // pointer to the Hash Table for O(1) searches
    lruc_entry_t *top; // pointer to the pot of the LRU cache
    void (*destroy_val_fn)(void*); // callback function for destroying an entry value

    u_int num_entries;
    u_int max_entries;

} lru_cache_t;

hash_table_t* ht_init(u_int length);
lru_cache_t* lruc_init_str(u_int max_entries);
lru_cache_t* lruc_init(u_int max_entries, void (*destroy_val_fn)(void*));

void ht_insert(hash_table_t *ht, lruc_entry_t *lruc_e, const char *key);
void ht_delete(hash_table_t *ht, const char *key);
void ht_destroy(hash_table_t* ht);
int lruc_insert_str(lru_cache_t *lruc, const char *key, const char* value);
int lruc_insert(lru_cache_t *lruc, const char *key, void* value);
void lruc_delete(lru_cache_t *lruc, const char *key);
void lruc_destroy(lru_cache_t *lruc);

lruc_entry_t* ht_search(const hash_table_t *ht, const char *key);
char* lruc_search_str(lru_cache_t *lruc, const char *key);
void* lruc_search(lru_cache_t *lruc, const char *key);

u_int hash_fn(const char* key);
u_int DJBHash(const char* str, u_int len);

void print_ht(hash_table_t *ht);
void print_lruc(lru_cache_t *lruc);
void clean_lruc(lru_cache_t *lruc);



