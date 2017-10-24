/*
 *   This is an implementation of a FIFO queue.
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

#ifndef __FIFO_QUEUE__
#define __FIFO_QUEUE__

#include <stdint.h>
#include <stdbool.h> 

#define MAX_FIFOQ_KEY_LEN 1024
#define DEFAULT_FIFOQ_LENGTH 10

typedef struct fifoq_entry {

    void* value;
    struct fifoq_entry *prev;
    struct fifoq_entry *next;

} fifoq_entry_t;

typedef struct fifo_queue { 

    size_t num_elements;
    size_t max_length;
    fifoq_entry_t* first;
    fifoq_entry_t* last;

    bool copy_keys;
    bool copy_values;
    bool destroy_keys;
    bool destroy_values;
    size_t sizeof_values;
    void (*copy_val_fn)(void*, void*);
    void (*destroy_val_fn)(void*);

} fifo_queue_t;


fifo_queue_t* 
fifoq_init(size_t max_length, bool copy_keys, bool copy_values, 
        bool destroy_keys, bool destroy_values, size_t sizeof_values,
        void (*copy_val_fn)(void*,void*), void (*destroy_val_fn)(void*));

// value_size is needed only if copy_values was set to true in fifoq_init
void fifoq_insert(fifo_queue_t* q, char* key, void* value);
void fifoq_delete(fifo_queue_t* q, char* key);
void fifoq_destroy(fifo_queue_t* q);
fifoq_entry_t* fifoq_search(const fifo_queue_t* q, const char* key);

void print_fifoq(fifo_queue_t* q);

#endif // __FIFO_QUEUE__

