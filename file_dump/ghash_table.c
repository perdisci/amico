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

#include "ghash_table.h"


/* Initializes the Hash Table */
ghash_table_t* ght_init(size_t length,
                      bool copy_keys,
                      bool copy_values,
                      bool destroy_keys, 
                      bool destroy_values, 
                      size_t sizeof_values,
                      void (*copy_val_fn)(void*,void*),
                      void (*destroy_val_fn)(void*)) {
    

    ghash_table_t* ht = (ghash_table_t*)malloc(sizeof(ghash_table_t));
    if(length>0)
        ht->length = length;
    else
        ht->length = DEFAULT_GHT_LENGTH;
    ht->copy_keys = copy_keys;
    ht->copy_values = copy_values;
    ht->destroy_keys = destroy_keys;
    ht->destroy_values = destroy_values;
    ht->sizeof_values = sizeof_values;
    ht->copy_val_fn = copy_val_fn;
    ht->destroy_val_fn = destroy_val_fn;

    ht->vect = (ght_entry_t**)malloc(sizeof(ght_entry_t*) * ht->length);

    int i;    
    for(i=0; i < ht->length; i++)
        ht->vect[i] = NULL;

    return ht;
}


/* Deallocate memory for Hash Table */
void ght_destroy(ghash_table_t* ht) {

    ght_entry_t *v;
    uint32_t i;

    if(ht == NULL)
        return;

    for(i=0; i < ht->length; i++) {
        v = ht->vect[i];
        while(v != NULL) {
            ght_entry_t *p = v;
            v = v->next;
            if(ht->destroy_keys)
                free(p->key);
            if(ht->destroy_values) {
                if(ht->destroy_val_fn != NULL)
                    ht->destroy_val_fn(p->value);
                free(p->value);
            }
            free(p);
        }
    }

    free(ht->vect);

    free(ht); 
}


void ght_insert(ghash_table_t *ht, char *key, void* value) {

    ght_entry_t *v;

    uint32_t h = _ghash_fn(key) % ht->length;
    ght_entry_t *e = (ght_entry_t*)malloc(sizeof(ght_entry_t));

    if(ht->copy_keys) {
        size_t key_len = strnlen(key,MAX_GHT_KEY_LEN);
        e->key = (char*)malloc(sizeof(char)*(key_len+1));
        strncpy(e->key,key,key_len);
        e->key[key_len]='\0';
    }
    else {
        e->key = key;
    }

    if(ht->copy_values) {
        e->value = (void*)malloc(ht->sizeof_values);
        if(ht->copy_val_fn != NULL) { // Deep copy:
            ht->copy_val_fn(e->value, value);
        }
        else // Shallow copy:
            memcpy(e->value,value,ht->sizeof_values);
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


void ght_delete(ghash_table_t *ht, char *key) {

    ght_entry_t *v;
    ght_entry_t *prev;

    uint32_t h = _ghash_fn(key) % ht->length;

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
                if(ht->destroy_values) {
                    if(ht->destroy_val_fn != NULL)
                        ht->destroy_val_fn(v->value);
                    free(v->value);
                }
                free(v);
                return;
            }
            prev = v;    
            v = v->next;
        } while(v != NULL);
    }
    
    return;

}

/* Searches Hash Table */
ght_entry_t* ght_search(const ghash_table_t *ht, const char *key) {

    ght_entry_t *v;

    uint32_t h = _ghash_fn(key) % ht->length;
    v = ht->vect[h];

    while(v != NULL) {
        if(strcmp(key, v->key) == 0)
            return v;
        v = v->next;
    }

    return NULL;
}


uint32_t _ghash_fn(const char* key) {

    #define MAX_DJBHASH_ITER 256
    return _DJBHash(key, strnlen(key, MAX_DJBHASH_ITER));

}


/* The following hash function has been borrowed
 * and slightly modified from
 * http://www.partow.net/programming/hashfunctions/
 * Author: Arash Partow
 */
uint32_t _DJBHash(const char* str, size_t len)
{
   uint32_t hash = 5381;
   uint32_t i    = 0;

   for(i = 0; i < len; i++)
   {
      hash = ((hash << 5) + hash) + (str[i]);
   }

   return hash;
}
/***/


void print_ght(ghash_table_t *ht) {   

    ght_entry_t *v;
    uint32_t i;

    if(ht == NULL)
        return;

    printf("=================\n");
    for(i=0; i < ht->length; i++) {
        v = ht->vect[i];
        if(v != NULL) {
            printf("(%p) %s", v, v->key);
            while(v->next!=NULL) {
                v = v->next;
                printf(" | (%p) %s", v, v->key);
            }
            printf("\n");
        }
    }
    printf("=================\n");

}


