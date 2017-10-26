/*
 *   This is an implementation of an FIFO queue.
 *   Copyright (C) 2017  Roberto Perdisci (perdisci@cs.uga.edu)
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

    if(max_length>0)
        q->max_length = max_length;
    else
        q->max_length = DEFAULT_FIFOQ_LENGTH;
    q->num_elements = 0;

    q->first = NULL;
    q->last = NULL;
    q->cursor=NULL;

    q->copy_values = copy_values;
    q->destroy_values = destroy_values;
    q->sizeof_values = sizeof_values;
    q->copy_val_fn = copy_val_fn;
    q->destroy_val_fn = destroy_val_fn;

    return q;
}


void fifoq_destroy(fifo_queue_t* q) {

    if(q == NULL)
        return;

    fifoq_entry_t *v = q->first;

    while(v != NULL) {
        fifoq_entry_t* p = v;
        v = v->prev;
        fifoq_delete_element(q,p);
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

    q->num_elements++;
    if(q->first == NULL) { // empty queue
        q->first = e;
        q->last  = e;
    }
    else {
        q->last->prev = e;
        e->next = q->last;   
        q->last = e;

        if(q->num_elements > q->max_length) {
            // remove first element

            fifoq_entry_t *f = q->first;
            fifoq_entry_t *s = q->first->prev; 

            s->next = NULL;
            q->first = s;
            fifoq_delete_element(q,f);
            q->num_elements--; 
        }
    }
}


void fifoq_delete_element(fifo_queue_t* q, fifoq_entry_t* e) {

    if(e != NULL) {
        if(q->destroy_values) {
            if(q->destroy_val_fn != NULL)
                q->destroy_val_fn(e->value);
            free(e->value);
        }
        free(e);
    }
}

void* fifoq_get_first_value(fifo_queue_t *q) {
    return q->first->value;
}

void* fifoq_get_last_value(fifo_queue_t *q) {
    return q->last->value;
}

void* fifoq_get_next_value(fifo_queue_t *q) {
    if(q->cursor == NULL)
        return NULL;

    fifoq_entry_t* v = q->cursor;
    q->cursor = q->cursor->prev;
    return v->value;
}

void fifoq_reset_cursor(fifo_queue_t *q) {
    q->cursor = q->first;
}

void print_fifoq(fifo_queue_t *q, void (*print_val_fn)(void*)) {   
    
    if(q == NULL)
        return;

    fifoq_entry_t* v = q->first;

    printf("=Q===============\n");
    printf("Elements: %lu\n", q->num_elements);
    uint16_t i = 0;
    while(v!=NULL) {
        printf("%u:(%p) :: ", i++, v);
        print_val_fn(v->value);
        printf("\n");
        v = v->prev;
    }
    printf("=================\n");

}

