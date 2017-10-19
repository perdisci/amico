/*
 *   This is an implementation of a generic FIFO queue.
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
#define __FIFO QUEUE__

#define MAX_QUEUE_LEN 20

typedef unsigned int u_int;

typedef struct queue_entry {

    void* value;
    struct queue_entry *next;

} queue_entry_t;

typedef struct fifo_queue {

    u_int max_len;
    u_int curr_len;
    queue_entry_t* head;
    queue_entry_t* tail;

} fifo_queue_t;

fifo_queue_t* queue_init(u_int max_len, short destroy_values);

void queue_insert(fifo_queue_t* q, void* value, short copy, size_t value_size);
void queue_delete(fifo_queue_t* q, int index);
void queue_destroy(fifo_queue_t* q);

void* queue_head(const fifo_queue_t* q);
void* queue_tail(const fifo_queue_t* q);
void* queue_at(const fifo_queue_t* q, int index);
void* queue_next(void* v);

void print_queue(fifo_queue_t *q);


#endif // __FIFO_QUEUE__
