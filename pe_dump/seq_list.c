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

#include "seq_list.h"

seq_list_t *seq_list_init(void) {

    seq_list_t *l = (seq_list_t*)malloc(sizeof(seq_list_t));
    if(l == NULL) {
        printf("Failed to initialize seq_list! Out of memory???\n");
        fflush(stdout);
        exit(1);
    }

    memset(l,0,sizeof(seq_list_t));
    l->head = NULL;
    l->tail = NULL;
    l->next = NULL;

    return l;
}

void seq_list_destroy(seq_list_t* l, int mz_found) {

    if(mz_found) {
        printf("Calling seq_list_destroy!!!\n");
        fflush(stdout);
    }

    if(l == NULL)
        return;

    seq_list_entry_t *h = l->head;
    seq_list_entry_t *n;

    while(h != NULL) {
        n = h->next;
        free(h);
        h = n;
    }

    l->head = NULL;
    l->tail = NULL;
    l->next = NULL;
    
    free(l);

    if(mz_found) {
        printf("Destroyed seq_list!!!\n");
        fflush(stdout);
    }
}

void seq_list_insert(seq_list_t *l, u_int i, u_int j) {

    if(l == NULL)
        return;

    seq_list_entry_t *e = (seq_list_entry_t*)malloc(sizeof(seq_list_entry_t));
    if(e == NULL) {
        printf("Error allocating memory for insering element in seq_list; Out of memory???\n");
        fflush(stdout);
        exit(1);
    }

    // initialize the new element
    memset(e,0,sizeof(seq_list_entry_t));
    e->i = i;
    e->j = j;
    e->next = NULL;
    
    if(l->head == NULL) {
        l->head = e;
        l->tail = e;
        l->next = e;

        return;
    }

    if(l->tail == NULL) {
        printf("Error: list tail cannot be null here!\n");
        fflush(stdout);
        exit(1);
    }
    l->tail->next = e;
    l->tail = e;
    
}

seq_list_entry_t *seq_list_head(seq_list_t *l) {

    if(l == NULL)
        return NULL;

    return l->head;
}

seq_list_entry_t *seq_list_tail(seq_list_t *l) {

    if(l == NULL)
        return NULL;

    return l->tail;
}

seq_list_entry_t *seq_list_next(seq_list_t *l) {

    if(l == NULL)
        return NULL;

    if(l->next == NULL)
        return NULL;

    seq_list_entry_t *n = l->next;
    l->next = l->next->next;

    return n;

}

void seq_list_restart_from_head(seq_list_t *l) {

    if(l == NULL)
        return;

    l->next = l->head;

}

void seq_list_print(seq_list_t *l) {

    if(l == NULL)
        return;

    seq_list_entry_t *e = l->head;
    while(e != NULL) {
        printf("(%u,%u) ", e->i, e->j);
        e = e->next;
    }
    printf("\n");

}

/* For debugging purposes */
/**
int main(void) {

    seq_list_t *l = seq_list_init();

    seq_list_insert(l,1,10);
    seq_list_insert(l,5,8);
    seq_list_insert(l,11,100);
    seq_list_insert(l,45,190);

    seq_list_print(l);

    seq_list_destroy(l);

    return 0;

}
**/
