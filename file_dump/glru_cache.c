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
#include "glru_cache.h"

// #define GLRUC_DEBUG
#define GHT_SIZE_FACTOR 10
#define GLRUC_MIN_ENTRIES 10



/* Initializes the LRU cache */
glru_cache_t* glruc_init(size_t max_entries, void (*destroy_val_fn)(void*)) {

    glru_cache_t* lruc = (glru_cache_t*)malloc(sizeof(glru_cache_t));
    lruc->ht = ght_init(max_entries);
    lruc->top = NULL;
    
    lruc->copy_keys = copy_keys;
    lruc->copy_values = copy_values;
    lruc->destroy_keys = destroy_keys;
    lruc->destroy_values = destroy_values;
    lruc->sizeof_values = sizeof_values;
    lruc->copy_val_fn = copy_val_fn;
    lruc->destroy_val_fn = destroy_val_fn;

    lruc->num_entries = 0;
    lruc->max_entries = GLRUC_MIN_ENTRIES; // we should force at least these many entries
    if(max_entries > GLRUC_MIN_ENTRIES)
        lruc->max_entries = max_entries;

    return lruc;
}


/* Deallocate memory for LRU cache */
void glruc_destroy(glru_cache_t *lruc) {

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
        glruc_entry_t *t = lruc->top;
        lruc->top = lruc->top->next; 
        free(t->key);
        if(t->value != NULL) {
            lruc->destroy_val_fn(t->value);
            t->value = NULL;
        }
        free(t);
    }

    ht_destroy(lruc->ht);
    lruc->ht = NULL;

    free(lruc);

}


int glruc_insert(glru_cache_t *lruc, const char *key, void* value) {

    if(key == NULL)
        return -1;

    if(glruc_search(lruc, key)!=NULL) 
        return -1;

    lruc->num_entries++;
    #ifdef LRUC_DEBUG
    printf("Inserting %u\n", lruc->num_entries);
    #endif

    glruc_entry_t *e = (glruc_entry_t*)malloc(sizeof(glruc_entry_t));
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
        // printf("LRUC is full!\n");
        // fflush(stdout);

        e->next = lruc->top;
        e->prev = lruc->top->prev->prev;
        lruc->top->prev->prev->next = e;
        glruc_entry_t *tmp = lruc->top->prev;
        lruc->top->prev = e;

        // evict from the cache
        ht_delete(lruc->ht, tmp->key);
        free(tmp->key);
        if(tmp->value != NULL)
            lruc->destroy_val_fn(tmp->value);
        free(tmp);

        lruc->num_entries--;

        // printf("Removed LRU element; inserted the new one!\n");
        // fflush(stdout);
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


// Delete an entry from the LRU cache
void glruc_delete(glru_cache_t *lruc, const char *key) {

    glruc_entry_t *e = ht_search(lruc->ht, key);

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


void* glruc_search(glru_cache_t *lruc, const char *key) {

    glruc_entry_t *e = ht_search(lruc->ht, key);

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

        if((t - e->time) > MAX_LRUC_TTL) {
            if(lruc->destroy_val_fn != NULL) {
                lruc->destroy_val_fn(e->value);
                e->value = NULL;
            }
            glruc_delete(lruc, e->key);
        }
        else
            break;

    } while(lruc->top!=NULL);

}


void print_lruc(glru_cache_t *lruc) {

    if(lruc==NULL)
        return;

    if(lruc->top == NULL)
        return;    

    glruc_entry_t *e = lruc->top;
    
    do {
        #ifdef LRUC_DEBUG
        printf("LRU_ENTRY: (k=%s , v=%s)\n", e->key, e->value);
        #endif
        e = e->next;
    } while(e != lruc->top);

}

