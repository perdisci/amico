
// Author: Roberto Perdisci <perdisci@cs.uga.edu>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int u_int;


//////////////////////////////////////////////////////////////
// This is an implementation of a siple list that holds pairs:
// (sequence_number, payload_size)
//////////////////////////////////////////////////////////////

typedef struct seq_list_entry {

    u_int sn; // sequence number
    u_int ps; // payload size 
    struct seq_list_entry *next;

} seq_list_entry_t;

typedef struct seq_list {

    seq_list_entry_t *head;
    seq_list_entry_t *tail;
    seq_list_entry_t *next;

} seq_list_t;

seq_list_t* seq_list_init(void);
void seq_list_destroy(seq_list_t* l, int mz_found);
void seq_list_insert(seq_list_t *l, u_int i, u_int j);
seq_list_entry_t *seq_list_head(seq_list_t *l);
seq_list_entry_t *seq_list_tail(seq_list_t *l);
seq_list_entry_t *seq_list_next(seq_list_t *l);
void seq_list_restart_from_head(seq_list_t *l);
void seq_list_restart_from_element(seq_list_t *l, seq_list_entry_t *e);
u_int seq_list_get_seq_num(seq_list_entry_t *e);
u_int seq_list_get_payload_size(seq_list_entry_t *e);
void seq_list_print(seq_list_t *l);

