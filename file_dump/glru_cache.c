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
#include <time.h>
#include "glru_cache.h"

// #define GLRUC_DEBUG
#define GHT_SIZE_FACTOR 3
#define GLRUC_MIN_ENTRIES 10



/* Initializes the LRU cache */
glru_cache_t* glruc_init(size_t max_entries, uint16_t ttl, 
            bool copy_keys, bool copy_values,
            bool destroy_keys, bool destroy_values, size_t sizeof_values,
            void (*copy_val_fn)(void*,void*), void (*destroy_val_fn)(void*)) {

    glru_cache_t* lruc = (glru_cache_t*)malloc(sizeof(glru_cache_t));

    lruc->top = NULL;
    
    lruc->copy_keys = copy_keys;
    lruc->copy_values = copy_values;
    lruc->destroy_keys = destroy_keys;
    lruc->destroy_values = destroy_values;
    lruc->sizeof_values = sizeof_values;
    lruc->copy_val_fn = copy_val_fn;
    lruc->destroy_val_fn = destroy_val_fn;

    lruc->ttl = MAX_GLRUC_TTL; // default ttl
    if(ttl>0)
        lruc->ttl = ttl;

    lruc->num_entries = 0;
    lruc->max_entries = GLRUC_MIN_ENTRIES; // force at least these many entries
    if(max_entries > GLRUC_MIN_ENTRIES)
        lruc->max_entries = max_entries;

    lruc->ht = ght_init(max_entries*GHT_SIZE_FACTOR, 
                            false, false, false, false, 0, NULL, NULL);

    return lruc;
}


/* Deallocate memory for LRU cache */
void glruc_destroy(glru_cache_t *lruc) {

    if(lruc == NULL)
        return;

    if(lruc->top == NULL)
        return;

    if(lruc->top->prev == NULL) { // only one entry...
        if(lruc->destroy_keys)
            free(lruc->top->key);
        if(lruc->top->value != NULL) {
            if(lruc->destroy_values) {
                if(lruc->destroy_val_fn != NULL)
                    lruc->destroy_val_fn(lruc->top->value);
                free(lruc->top->value);
            }
        }
        free(lruc->top);
        return;
    }

    lruc->top->prev->next = NULL; // break the circular list
    while(lruc->top != NULL) {
        glruc_entry_t *t = lruc->top;
        lruc->top = lruc->top->next; 
        if(lruc->destroy_keys)
            free(t->key);
        if(t->value != NULL) {
            if(lruc->destroy_values) {
                if(lruc->destroy_val_fn != NULL)
                    lruc->destroy_val_fn(t->value);
                free(t->value);
            }
            t->value = NULL;
        }
        free(t);
    }

    ght_destroy(lruc->ht);
    lruc->ht = NULL;

    free(lruc);

}


int glruc_insert(glru_cache_t *lruc, char *key, void* value) {

    if(key == NULL)
        return -1;

    if(glruc_search(lruc, key)!=NULL) 
        return -1;

    lruc->num_entries++;
    #ifdef GLRUC_DEBUG
    printf("Inserting %lu\n", lruc->num_entries);
    #endif

    glruc_entry_t *e = (glruc_entry_t*)malloc(sizeof(glruc_entry_t));

    if(lruc->copy_keys) {
        size_t key_len = strnlen(key,MAX_GLRUC_KEY_LEN);
        e->key = (char*)malloc(sizeof(char)*(key_len+1));
        strncpy(e->key,key,key_len);
        e->key[key_len]='\0';
    }
    else {
        e->key = key;
    }

    if(lruc->copy_values) {
        e->value = (void*)malloc(lruc->sizeof_values);
        if(lruc->copy_val_fn != NULL) { // Deep copy:
            lruc->copy_val_fn(e->value, value);
        }
        else // Shallow copy:
            memcpy(e->value,value,lruc->sizeof_values);
    }
    else {
        e->value = value;
    }

    e->time = time(NULL);

    /* the cache is implemented as a doubly-linked circular list */
    if(lruc->top == NULL) {
        e->next = e;
        e->prev = e;
    }
    else {
        // printf("LRUC is full!\n");
        // fflush(stdout);

        glruc_entry_t* last = lruc->top->prev;
        e->next = last;
        e->prev = last->prev;
        last->prev->next = e;
        last->prev = e;

        if(lruc->num_entries > lruc->max_entries) {
            // evict last LRUC element from the cache
            glruc_delete(lruc, last->key);
        }
    }

    lruc->top = e;

    /* Insert e in the Hash Table for fast, O(1) searches */
    ght_insert(lruc->ht, e->key, e);
    
    #ifdef GLRUC_DEBUG 
        printf("Inserted %lu!\n", lruc->num_entries);
        printf("GLRUC: HT print: \n");
        print_ght(lruc->ht);
    #endif

    glruc_prune(lruc); // remove stale entries

    return 0;
}


// Delete an entry from the LRU cache
void glruc_delete(glru_cache_t *lruc, char *key) {

    ght_entry_t* h = ght_search(lruc->ht, key);
    if(h == NULL)
        return;

    glruc_entry_t* e = h->value;

    if(e!=NULL) {
        if(lruc->top == e && lruc->top->next == e) // only one entry!
            lruc->top = NULL;
        else {
            if(lruc->top == e)
                lruc->top = e->next;
            
            e->prev->next = e->next;
            e->next->prev = e->prev;
        }

        ght_delete(lruc->ht, e->key);
        if(lruc->destroy_keys)
            free(e->key);
        if(e->value != NULL) {
            if(lruc->destroy_values) {
                if(lruc->destroy_val_fn != NULL)
                    lruc->destroy_val_fn(e->value);
                free(e->value);
            }
        }
        free(e);

        lruc->num_entries--;
    }
}


glruc_entry_t* glruc_search(glru_cache_t *lruc, const char *key) {

    if(lruc->top == NULL)
        return NULL;

    ght_entry_t* h = ght_search(lruc->ht, key);
    if(h == NULL)
        return NULL;

    glruc_entry_t* e = h->value;

    #ifdef GLRUC_DEBUG
        printf("glruc_search: glruc_entry_t (e=%p) (e->key=%p) (e->value=%p)\n", e, e->key, e->value);
        fflush(stdout);
    #endif

    if(e == NULL)
        return NULL;

    #ifdef GLRUC_DEBUG
        printf("Found element in Hash Table (key:%s)\n", e->key);
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

    return e;
}


void glruc_prune(glru_cache_t *lruc) {

    if(lruc==NULL)
        return;

    if(lruc->top == NULL)
        return;    

    time_t t = time(NULL);
    // printf("Current Time = %u\n", t);

    do {
        glruc_entry_t *e = lruc->top->prev;
        // printf("e Time = %u\n", e->time);

        if((t - e->time) > lruc->ttl)
            glruc_delete(lruc, e->key);
        else
            break;

    } while(lruc->top!=NULL);

}


void print_glruc(glru_cache_t *lruc) {

    if(lruc==NULL)
        return;

    if(lruc->top == NULL)
        return;    

    glruc_entry_t *e = lruc->top;
    
    do {
        #ifdef GLRUC_DEBUG
        printf("LRU_ENTRY: (k=%s)\n", e->key);
        #endif
        e = e->next;
    } while(e != lruc->top);

}

