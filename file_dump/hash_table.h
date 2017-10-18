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

#ifndef __HASH_TABLE__
#define __HASH_TABLE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEY_LEN 1024
#define DEFAULT_HT_LENGTH 1024*1024

typedef unsigned int u_int;

typedef struct ht_entry {

    char *key;
    void* value;
    struct ht_entry *next;

} ht_entry_t;

typedef struct hash_table {

    u_int length;
    ht_entry_t **vect;
    short destroy_keys;
    short destroy_values;

} hash_table_t;

hash_table_t* ht_init(u_int length, short destroy_keys, short destroy_values);

void ht_insert(hash_table_t *ht, char *key, void* value, short copy, size_t value_size);
void ht_delete(hash_table_t *ht, const char *key);
void ht_destroy(hash_table_t* ht);

void* ht_search(const hash_table_t *ht, const char *key);

u_int hash_fn(const char* key);
u_int DJBHash(const char* str, u_int len);

void print_ht(hash_table_t *ht);


#endif // __HASH_TABLE__
