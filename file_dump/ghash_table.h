/*
 *   This is an implementation of a generic hash table.
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

#ifndef __GHASH_TABLE__
#define __GHASH_TABLE__

#include <stdint.h>
#include <stdbool.h> 

#define MAX_GHT_KEY_LEN 1024
#define DEFAULT_GHT_LENGTH 1024*1024

typedef struct ght_entry {

    char *key;
    void* value;
    struct ght_entry *next;

} ght_entry_t;

typedef struct generic_hash_table {

    size_t length;
    ght_entry_t **vect;
    bool copy_keys;
    bool copy_values;
    bool destroy_keys;
    bool destroy_values;
    size_t sizeof_values;
    void (*copy_val_fn)(void*, void*);
    void (*destroy_val_fn)(void*);

} ghash_table_t;


ghash_table_t* 
ght_init(size_t length, bool copy_keys, bool copy_values, 
        bool destroy_keys, bool destroy_values, size_t sizeof_values,
        void (*copy_val_fn)(void*,void*), void (*destroy_val_fn)(void*));

// value_size is needed only if copy_values was set to true in ght_init
void ght_insert(ghash_table_t *ht, char *key, void* value);
void ght_delete(ghash_table_t *ht, char *key);
void ght_destroy(ghash_table_t* ht);
ght_entry_t* ght_search(const ghash_table_t *ht, const char *key);

void print_ght(ghash_table_t *ht);

uint32_t _ghash_fn(const char* key);
uint32_t _DJBHash(const char* str, size_t len);

#endif // __GHASH_TABLE__

