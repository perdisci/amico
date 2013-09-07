/*
 *   Copyright (C) 2011  Roberto Perdisci (perdisci@cs.uga.edu)
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

typedef unsigned int u_int;

typedef struct seq_list_entry {

    u_int i;
    u_int j;
    struct seq_list_entry *next;

} seq_list_entry_t;

typedef struct seq_list {

    seq_list_entry_t *head;
    seq_list_entry_t *tail;
    seq_list_entry_t *next;

} seq_list_t;

seq_list_t* seq_list_init(void);
void seq_list_destroy(seq_list_t* l);
void seq_list_insert(seq_list_t *l, u_int i, u_int j);
seq_list_entry_t *seq_list_head(seq_list_t *l);
seq_list_entry_t *seq_list_tail(seq_list_t *l);
seq_list_entry_t *seq_list_next(seq_list_t *l);
void seq_list_restart_from_head(seq_list_t *l);
void seq_list_print(seq_list_t *l);

