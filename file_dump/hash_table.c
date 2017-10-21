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
#include <stdbool.h>

#include "hash_table.h"


/* Initializes the Hash Table */
// NOTE(Roberto): destroy_values only means a "shallow" destroy
//  if value contains dynamically allocated objects, these will not 
//  be destroyed. This HT needs to be extended to handle those cases.
hash_table_t* ht_init(u_int length,
                      bool copy_keys,
                      bool copy_values,
                      bool destroy_keys, 
                      bool destroy_values, 
                      void (*destroy_val_fn)(void*)) {
    

    hash_table_t* ht = (hash_table_t*)malloc(sizeof(hash_table_t));
    if(length>0)
        ht->length = length;
    else
        ht->length = DEFAULT_HT_LENGTH;
    ht->destroy_keys = destroy_keys;
    ht->destroy_values = destroy_values;
    ht->destroy_val_fn = destroy_val_fn;
    ht->vect = (ht_entry_t**)malloc(sizeof(ht_entry_t*) * ht->length);

    int i;    
    for(i=0; i < ht->length; i++)
        ht->vect[i] = NULL;

    return ht;

}


/* Deallocate memory for Hash Table */
void ht_destroy(hash_table_t* ht) {

    ht_entry_t *v;
    u_int i;

    if(ht == NULL)
        return;

    for(i=0; i < ht->length; i++) {
        v = ht->vect[i];
        while(v != NULL) {
            ht_entry_t *p = v;
            v = v->next;
            if(ht->destroy_keys)
                free(p->key);
            if(ht->destroy_val_fn != NULL)
                destroy_val_fn(p->value);
            if(ht->destroy_values)
                free(p->value);
            free(p);
        }
    }
   
    free(ht->vect);
    ht->vect = NULL;

    free(ht); 

}


void ht_insert(hash_table_t *ht, char *key, void* value, size_t value_size) {

    ht_entry_t *v;

    u_int h = hash_fn(key) % ht->length;
    ht_entry_t *e = (ht_entry_t*)malloc(sizeof(ht_entry_t));

    if(ht->copy_keys) {
        size_t key_len = strnlen(key,MAX_KEY_LEN);
        e->key = (char*)malloc(sizeof(char)*(key_len+1));
        strncpy(e->key,key,key_len);
        e->key[key_len]='\0';
    }
    else {
        e->key = key;
    }

    if(ht->copy_values) {
        e->value = (void*)malloc(value_size);
        memcpy(e->value,value,value_size);
    }
    else {
        e->value = value;
    }

    e->next = NULL;

    v = ht->vect[h];
    if(v == NULL) {
        ht->vect[h] = e;
        return;
    }

    while(v->next != NULL)
        v = v->next;

    v->next = e;

}

/* Delete key from Hash Table */
void ht_delete(hash_table_t *ht, const char *key) {

    ht_entry_t *v;
    ht_entry_t *prev;

    u_int h = hash_fn(key) % ht->length;
    #ifdef LRUC_DEBUG 
        printf("key=%s, h=%u\n", key, h);
    #endif

    v = ht->vect[h];
    prev = NULL;
    if(v != NULL) {
        do {
            if(strcmp(key, v->key) == 0) {
                if(prev != NULL)
                    prev->next = v->next;
                else if(v->next != NULL)
                    ht->vect[h] = v->next;
                else
                    ht->vect[h] = NULL;
                if(ht->destroy_keys)
                    free(v->key);
                if(ht->destroy_val_fn != NULL)
                    destroy_val_fn(value);
                if(ht->destroy_values)
                    free(v->value);
                free(v);
                return;
            }
            prev = v;    
            v = v->next;
        } while(v != NULL);
    }
    
    return;

}

/* Searches an LRU cache entry using the Hash Table */
void* ht_search(const hash_table_t *ht, const char *key) {

    ht_entry_t *v;

    u_int h = hash_fn(key) % ht->length;
    v = ht->vect[h];

    if(v == NULL) 
        return NULL;

    while(v != NULL) {
        if(strcmp(key, v->key) == 0)
            return v->value;
        v = v->next;
    }

    return NULL;
}


u_int hash_fn(const char* key) {

    #define MAX_HASH_ITER 256
    return DJBHash(key, strnlen(key, MAX_HASH_ITER));

}


/* The following hash function has been borrowed
 * and slightly modified from
 * http://www.partow.net/programming/hashfunctions/
 * Author: Arash Partow
 */
u_int DJBHash(const char* str, u_int len)
{
   u_int hash = 5381;
   u_int i    = 0;

   for(i = 0; i < len; i++)
   {
      hash = ((hash << 5) + hash) + (str[i]);
   }

   return hash;
}
/***/


void print_ht(hash_table_t *ht) {   

    ht_entry_t *v;
    u_int i;

    if(ht == NULL)
        return;

    for(i=0; i < ht->length; i++) {
        v = ht->vect[i];
        if(v != NULL) {
            printf("HASH_TAB_ENTRY: %s", v->key);
            while(v->next!=NULL) {
                v = v->next;
                printf(" | %s", v->key);
            }
            printf("\n");
        }
    }

}


