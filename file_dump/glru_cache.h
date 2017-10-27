/*
 *   This is an implementation of a generic O(1) LRU cache.
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

#ifndef __GLRU_CACHE__
#define __GLRU_CACHE__

#include <stdint.h>
#include <stdbool.h> 
#include "ghash_table.h"

#define MAX_GLRUC_KEY_LEN MAX_GHT_KEY_LEN
#define MAX_GLRUC_TTL 10*60 // 10 minutes

typedef struct glruc_entry {

    char *key;
    void *value;
    time_t time;
    struct glruc_entry *prev;
    struct glruc_entry *next;

} glruc_entry_t;

typedef struct glru_cache {

    glruc_entry_t* top; // pointer to the top of the LRU cache
    ghash_table_t* ht;  // pointer to the Hash Table for O(1) searches

    uint16_t ttl;
    size_t num_entries;
    size_t max_entries;

    bool copy_keys;
    bool copy_values;
    bool destroy_keys;
    bool destroy_values;
    size_t sizeof_values;
    void (*copy_val_fn)(void*, void*);
    void (*destroy_val_fn)(void*);

} glru_cache_t;

glru_cache_t*
glruc_init(size_t max_entries, uint16_t ttl, bool copy_keys, bool copy_values,
            bool destroy_keys, bool destroy_values, size_t sizeof_values,
            void (*copy_val_fn)(void*,void*), void (*destroy_val_fn)(void*));

int glruc_insert(glru_cache_t *lruc, char *key, void* value);
glruc_entry_t* glruc_search(glru_cache_t *lruc, const char *key);
void glruc_delete(glru_cache_t *lruc, char *key);
void glruc_destroy(glru_cache_t *lruc);
void* glruc_pop_value(glru_cache_t *lruc, char *key);
void glruc_prune(glru_cache_t *lruc);

void print_glruc(glru_cache_t *lruc);


#endif // __GLRU_CACHE__

