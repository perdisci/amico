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

#include <time.h>
#include "lru-cache.h"

// #define LRUC_DEBUG
#define HT_SIZE_FACTOR 10

/* Initializes the Hash Table */
hash_table_t* ht_init(u_int length) {
    
    int i;    

    hash_table_t* ht = (hash_table_t*)malloc(sizeof(hash_table_t));
    ht->length = length * HT_SIZE_FACTOR;
    ht->vect = (ht_entry_t**)malloc(sizeof(ht_entry_t*) * ht->length);
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
            #ifdef LRUC_DEBUG 
                printf("Destroying ht vect entry!\n");
                fflush(stdout);
            #endif
            free(p);
        }
    }
   
    free(ht->vect);
    free(ht); 

}


void default_destroy_val_fn(void *v) {
    free(v);
}


/* Initializes the LRU cache in the special case of char* values */
lru_cache_t* lruc_init_str(u_int max_entries) {
    return lruc_init(max_entries, default_destroy_val_fn);
}


/* Initializes the LRU cache */
lru_cache_t* lruc_init(u_int max_entries, void (*destroy_val_fn)(void*)) {

    lru_cache_t* lruc = (lru_cache_t*)malloc(sizeof(lru_cache_t));
    lruc->ht = ht_init(max_entries);
    lruc->top = NULL;
    if(destroy_val_fn != NULL)
        lruc->destroy_val_fn = destroy_val_fn;
    else
        lruc->destroy_val_fn = default_destroy_val_fn;
    lruc->num_entries = 0;
    lruc->max_entries = max_entries;

    return lruc;
}


/* Deallocate memory for LRU cache */
void lruc_destroy(lru_cache_t *lruc) {

    if(lruc == NULL)
        return;

    if(lruc->top == NULL)
        return;

    if(lruc->top->prev == NULL) { // only one entry...
        free(lruc->top->key);
        if(lruc->top->value != NULL)
            lruc->destroy_val_fn(lruc->top->value);
        free(lruc->top);
        return;
    }

    lruc->top->prev->next = NULL; // break the circular list
    while(lruc->top != NULL) {
        lruc_entry_t *t = lruc->top;
        lruc->top = lruc->top->next; 
        free(t->key);
        if(t->value != NULL)
            lruc->destroy_val_fn(t->value);
        free(t);
    }

    ht_destroy(lruc->ht);
    free(lruc);

}


/* Inserts an element into the Hash Table
 * 'lruc_e' is a pointer to the (key,value) entry in the LRU cache
 * related to the 'key' parameter
 */
void ht_insert(hash_table_t *ht, lruc_entry_t *lruc_e, const char *key) {

    ht_entry_t *v;

    u_int h = hash_fn(key) % ht->length;
    ht_entry_t *e = (ht_entry_t*)malloc(sizeof(ht_entry_t));
    e->key = key;
    e->le = lruc_e;
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

/* Inserts and (key,value) pair in the LRU cache.
 * Notice that value could be NULL, but the key cannot be NULL
 */

int lruc_insert_str(lru_cache_t *lruc, const char *key, const char* value) {

    int ret = lruc_insert(lruc, key, NULL);    
    if(value!=NULL) {
        lruc_entry_t *e = ht_search(lruc->ht, key);
        e->value = (char*)malloc(sizeof(char)*(strlen(value)+1));
        strcpy(e->value, value);
    }

    return ret;

}

int lruc_insert(lru_cache_t *lruc, const char *key, void* value) {

    if(key == NULL)
        return;

    if(lruc_search(lruc, key)!=NULL) 
        return -1;

    lruc->num_entries++;
    #ifdef LRUC_DEBUG
    printf("Inserting %u\n", lruc->num_entries);
    #endif

    lruc_entry_t *e = (lruc_entry_t*)malloc(sizeof(lruc_entry_t));
    e->key = (char*)malloc(sizeof(char)*(strlen(key)+1));
    strcpy(e->key, key);
    e->value = value;
    e->time = time(NULL);

    /* the cache is implemented as a doubly-linked circular list */
    if(lruc->top == NULL) {
        e->next = e;
        e->prev = e;
    }
    else if(lruc->num_entries <= lruc->max_entries) {
        e->prev = lruc->top->prev;
        e->next = lruc->top;    

        lruc->top->prev->next = e;
        lruc->top->prev = e;
    }
    else {
        e->next = lruc->top;
        e->prev = lruc->top->prev->prev;
        lruc->top->prev->prev->next = e;
        lruc_entry_t *tmp = lruc->top->prev;
        lruc->top->prev = e;

        // evict from the cache
        ht_delete(lruc->ht, tmp->key);
        free(tmp->key);
        if(tmp->value != NULL)
            lruc->destroy_val_fn(tmp->value);
        free(tmp);

        lruc->num_entries--;
    }

    lruc->top = e;

    /* Insert e in the Hash Table for fast, O(1) searches */
    ht_insert(lruc->ht, e, e->key);
    
    #ifdef LRUC_DEBUG 
        printf("Inserted!\n", lruc->num_entries);
        print_ht(lruc->ht);
    #endif

    return 0;
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
                free(v);
                return;
            }
            prev = v;    
            v = v->next;
        } while(v != NULL);
    }
    
    return;

}

// Delete an entry from the LRU cache
void lruc_delete(lru_cache_t *lruc, const char *key) {

    lruc_entry_t *e = ht_search(lruc->ht, key);

    if(e!=NULL) {
        if(lruc->top == e && lruc->top->next == e) // only one entry!
            lruc->top = NULL;
        else {
            if(lruc->top == e)
                lruc->top = e->next;
            
            e->prev->next = e->next;
            e->next->prev = e->prev;
        }

        ht_delete(lruc->ht, e->key);
        free(e->key);
        if(e->value != NULL)
            lruc->destroy_val_fn(e->value);
        free(e);

        lruc->num_entries--;
    }

}


/* Searches an LRU cache entry using the Hash Table */
lruc_entry_t* ht_search(const hash_table_t *ht, const char *key) {

    ht_entry_t *v;

    u_int h = hash_fn(key) % ht->length;
    v = ht->vect[h];

    #ifdef LRUC_DEBUG
        printf("Hash Key = %u\n", h);
        printf("v = %p\n", v);
        fflush(stdout);
    #endif

    if(v == NULL) 
        return NULL;

    while(v != NULL) {
        #ifdef LRUC_DEBUG
            printf("v is not null!\n");
            printf("key = %s\n", key);
            printf("v->key = %s\n", v->key);
            fflush(stdout);
        #endif

        if(strcmp(key, v->key) == 0)
            return v->le;
        v = v->next;
    }

    #ifdef LRUC_DEBUG
        printf("HT entry not found! Returing NULL\n");
        fflush(stdout);
    #endif 

    return NULL;

}


char* lruc_search_str(lru_cache_t *lruc, const char *key) {
    return (char*)lruc_search(lruc, key);
}


void* lruc_search(lru_cache_t *lruc, const char *key) {

    lruc_entry_t *e = ht_search(lruc->ht, key);

    #ifdef LRUC_DEBUG
        printf("e = %p\n", e);
        fflush(stdout);
    #endif

    if(e == NULL)
        return NULL;

    #ifdef LRUC_DEBUG
        printf("Found element in Hash Table (%s, %s)\n", e->key, e->value);
        fflush(stdout);
    #endif 

    
    if(e != lruc->top) {
            /* e is the most recently used: move it to the top, if needed! */
            e->prev->next = e->next;
            e->next->prev = e->prev;
            e->prev = lruc->top->prev;
            e->next = lruc->top;
            lruc->top->prev->next = e;
            lruc->top->prev = e;
            lruc->top = e;   
    }

    e->time = time(NULL);

    if(e->value != NULL)
        return e->value;
    
    return e->key; // we don't want to return NULL if there is a match!
                       // even if the value was NULL

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
            #ifdef LRUC_DEBUG 
            printf("HASH_TAB_ENTRY: %s", v->key);
            #endif
            while(v->next!=NULL) {
                v = v->next;
                #ifdef LRUC_DEBUG
                printf(" | %s", v->key);
                #endif
            }
            #ifdef LRUC_DEBUG
            printf("\n");
            #endif
        }
    }

}



void clean_lruc(lru_cache_t *lruc) {

    if(lruc==NULL)
        return;

    if(lruc->top == NULL)
        return;    

    time_t t = time(NULL);
    // printf("Current Time = %u\n", t);

    do {
        lruc_entry_t *e = lruc->top->prev;
        // printf("e Time = %u\n", e->time);

        if((t - e->time) > MAX_LRUC_TTL)
            lruc_delete(lruc, e->key);
        else
            break;

    } while(lruc->top!=NULL);

}


void print_lruc(lru_cache_t *lruc) {

    if(lruc==NULL)
        return;

    if(lruc->top == NULL)
        return;    

    lruc_entry_t *e = lruc->top;
    
    do {
        #ifdef LRUC_DEBUG
        printf("LRU_ENTRY: (k=%s , v=%s)\n", e->key, e->value);
        #endif
        e = e->next;
    } while(e != lruc->top);

}


/* A little bit of testing to make sure things are working correctly... */
/**
int main() {

    char k[256];
    char v[256];
    int i;

    printf("Initializing LRU cache...\n");
    lru_cache_t *lruc = lruc_init_str(10);        
    fflush(stdout);


    for(i=0; i < 10; i++) {
        printf("Inserting (key,val)\n");
        fflush(stdout);
        sprintf(k, "key%d", (i+1));
        sprintf(v, "value%d", (i+1));
        lruc_insert_str(lruc, k, v);
        print_ht(lruc->ht);
        printf("###################\n");
    }

    print_ht(lruc->ht);
    print_lruc(lruc);
    printf("###################\n");

    sprintf(k, "key%d", 8);
    printf("Searchign for k=%s\n", k);
    strcpy(v, lruc_search_str(lruc, k));
    printf("Found v=%s\n", v);
    printf("###################\n");

    for(i=10; i < 15; i++) {
        printf("Inserting (key,val)\n");
        fflush(stdout);
        sprintf(k, "key%d", (i+1));
        sprintf(v, "value%d", (i+1));
        lruc_insert_str(lruc, k, v);
        print_ht(lruc->ht);
        printf("###################\n");

    }

    print_ht(lruc->ht);
    print_lruc(lruc);

    for(i=6; i < 13; i++) {
        sprintf(k, "key%d", i);
        printf("Searchign for k=%s\n", k);
        strcpy(v, lruc_search_str(lruc, k));
        printf("Found v=%s\n", v);
        printf("###################\n");
    }

    print_ht(lruc->ht);
    print_lruc(lruc);
    printf("###################\n");

    for(i=16; i < 18; i++) {
        printf("Inserting (key,val)\n");
        fflush(stdout);
        sprintf(k, "key%d", i);
        sprintf(v, "value%d", i);
        lruc_insert_str(lruc, k, v);
        print_ht(lruc->ht);
        printf("###################\n");

    }

    print_ht(lruc->ht);
    print_lruc(lruc);
    printf("###################\n");

    sprintf(k, "key%d", 1);
    printf("Searchign for k=%s\n", k);
    if(lruc_search_str(lruc, k)!=NULL) {
        strcpy(v, lruc_search_str(lruc, k));
        printf("Found v=%s\n", v);
    }
    printf("###################\n");

    lruc_destroy(lruc);
    printf("Destroyed!\n");

}
**/

