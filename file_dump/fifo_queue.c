/*
 *   This is an implementation of an FIFO queue.
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


/* Initializes the FIFO queue */
fifo_queue_t* fifoq_init(size_t max_length,
                      bool copy_values,
                      bool destroy_values, 
                      size_t sizeof_values,
                      void (*copy_val_fn)(void*,void*),
                      void (*destroy_val_fn)(void*)) {
    

    fifo_queue_t* q = (fifo_queue_t*)malloc(sizeof(fifo_queue_t));

    if(length>0)
        q->max_length = max_length;
    else
        q->max_length = DEFAULT_FIFOQ_LENGTH;
    q->num_elements = 0;

    q->first = NULL;
    q->last = NULL;

    q->copy_values = copy_values;
    q->destroy_values = destroy_values;
    q->sizeof_values = sizeof_values;
    q->copy_val_fn = copy_val_fn;
    q->destroy_val_fn = destroy_val_fn;

    return q;
}


/* Deallocate memory for FIFO queue */
void fifoq_destroy(fifo_queue_t* q) {


    if(q == NULL)
        return;

    fifoq_entry_t *v = q->first;

    while(v != NULL) {
        fifoq_entry_t* p = v;
        v = v->prev;
        fifoq_delete_element(p);
    }
   
    free(q);
}


void fifoq_insert(fifo_queue_t* q, void* value) {

    fifoq_entry_t *e = (fifoq_entry_t*)malloc(sizeof(fifoq_entry_t));

    if(q->copy_values) {
        e->value = (void*)malloc(q->sizeof_values);
        if(q->copy_val_fn != NULL) { // Deep copy:
            q->copy_val_fn(e->value, value);
        }
        else // Shallow copy:
            memcpy(e->value,value,q->sizeof_values);
    }
    else {
        e->value = value;
    }

    e->prev = NULL;
    e->next = NULL;

    if(first == NULL) { // empty queue
        q->first = e;
        q->last  = e;
    }
    else {
        q->last->prev = e;
        e->next = q->last;   
        q->last = e;
        q->num_elements++;

        if(q->num_elements > q->max_length) {
            // remove first element

            fifoq_entry_t *f = q->first;
            fifoq_entry_t *s = q->first->prev; 

            s->next = NULL;
            q->first = s;
            fifoq_delete_element(f);
            q->num_elements--; 
        }
    }
}


void fifoq_delete_element(fifoq_entry_t* e) {

    if(e != NULL) {
        if(q->destroy_values) {
            if(q->destroy_val_fn != NULL)
                q->destroy_val_fn(e->value);
            free(e->value);
        }
        free(e);
        return;
    }
}

/* Searches FIFO queue */
fifoq_entry_t* fifoq_search(const fifo_queue_t *q) {

    fifoq_entry_t *v;

    uint32_t h = _ghash_fn(key) % q->length;
    v = q->vect[h];

    while(v != NULL) {
        if(strcmp(key, v->key) == 0)
            return v;
        v = v->next;
    }

    return NULL;
}

void print_queue(fifo_queue_t *q) {   

    fifoq_entry_t* v = q->first;


    printf("=================\n");
    uint16_t i = 0;
    while(v!=NULL) {
        printf("%u:(%p)\n", i++, v);
        v = v->prev;
    }
    printf("=================\n");

}


