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

#include "fifo_queue.h"


/* Initializes the queue */
// NOTE(Roberto): destroy_values only means a "shallow" destroy
//  if value contains dynamically allocated objects, these will not 
//  be destroyed. This HT needs to be extended to handle those cases.
hash_table_t* ht_init(u_int max_len, short destroy_values) {
    
    fifo_queue_t* q = (fifo_queue_t*)malloc(sizeof(fifo_queue_t));
    if(max_len>0)
        q->max_len = max_len;;
    else
        q->max_len = MAX_QUEUE_LEN;
    q->destroy_values = destroy_values;

    q->curr_len = 0;
    q->head = NULL;
    q->tail = NULL;

    return q;

}


/* Deallocate memory for Queue */
void ht_destroy(fifo_queue_t* q) {

    queue_entry_t *v;
    u_int i;

    if(q == NULL)
        return;

    v = q->head;
    while(v != NULL) {
        queue_entry_t *p = v;
        v = v->next;
        if(q->destroy_values)
            free(p->value);
        free(p);
    }
   
    free(q); 

}


void queue_insert(fifo_queue_t* q, void* value, short copy, size_t value_size) {

    queue_entry_t *v = q->tail;

    queue_entry_t *e = (queue_entry_t*)malloc(sizeof(queue_entry_t));

    if(copy) {
        e->value = (void*)malloc(value_size);
        memcpy(e->value,value,value_size);
    }
    else {
        e->value = value;
    }

    e->next = NULL;

    if(q->head == NULL) {
        q->head = e;
        q->tail = e;
    }
    else {
        q->tail->next = e;
        q->tail = e;
    }
    q->curr_len++;
        
    if(q->curr_len >= q->max_len) {
        queue_delete_head(q);
    }
}

/* Remove head and return its value */
void* queue_pop(fifo_queue_t* q) {

    if(q->head == NULL)
        return NULL;

    queue_entry_t *v = q->head;
    q->head = v->next;
    return v;
    
    u_int i = 0;
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


