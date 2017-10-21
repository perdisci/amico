/*
 *   This is an implementation of a generic LRU cache.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_LRUC_TTL 5*60 // 5 minutes

typedef unsigned int u_int;

typedef struct glruc_entry {

    char* key;
    void *value;
    time_t time;
    struct lruc_entry *prev;
    struct lruc_entry *next;

} glruc_entry_t;

typedef struct glru_cache {

    lruc_entry_t *top; // pointer to the top of the LRU cache
    void (*destroy_val_fn)(void*); // callback function for destroying an entry value

    u_int num_entries;
    u_int max_entries;

} glru_cache_t;

glru_cache_t* glruc_init(u_int max_entries, bool destroy_keys, bool destroy_values, 
                         void (*destroy_val_fn)(void*));

int glruc_insert(glru_cache_t *lruc, char *key, void* value, bool copy, size_t value_size);
void glruc_delete(glru_cache_t *lruc, glruc_entry_t* ptr);
void glruc_delete(glru_cache_t *lruc, char *key);
void glruc_destroy(glru_cache_t *lruc);
void* glruc_search(glru_cache_t *lruc, const char *key);

void glruc_prune(lru_cache_t *lruc);

void print_lruc(lru_cache_t *lruc);


#endif // __GLRU_CACHE__
