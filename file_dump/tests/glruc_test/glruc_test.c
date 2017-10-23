/* 
 * Author: Roberto Perdisci (perdisci@cs.uga.edu)
 *
 * Testing of generic Hash Table
 */

// To use Valgrind:
// G_SLICE=always-malloc G_DEBUG=gc-friendly  valgrind -v --tool=memcheck --leak-check=full --num-callers=40 --log-file=valgrind.log ./glruc_test

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>

#include "../../glru_cache.h"

#define MAX_KEY_LEN MAX_GLRUC_KEY_LEN
#define MAX_URL_LEN 512
#define MAX_UA_LEN 32

typedef struct http_req_value {
    char url[MAX_URL_LEN+1];
    char ua[MAX_URL_LEN+1]; // generalized user agent string
} http_req_value_t;

typedef struct http_req_value_dyn {
    char* url;
    char* ua; // generalized user agent string
} http_req_value_dyn_t;

void copy_http_req_value_dyn(void* dst_v, void* src_v) {

    http_req_value_dyn_t* dv = (http_req_value_dyn_t*)dst_v;
    http_req_value_dyn_t* sv = (http_req_value_dyn_t*)src_v;
    
    size_t surl_len = strnlen(sv->url,MAX_URL_LEN);
    size_t sua_len = strnlen(sv->ua,MAX_UA_LEN);

    dv->url = (char*)malloc(sizeof(char)*(surl_len+1));
    dv->ua  = (char*)malloc(sizeof(char)*(sua_len+1));

    strncpy(dv->url, sv->url, surl_len);
    dv->url[surl_len]='\0';

    strncpy(dv->ua, sv->ua, sua_len);
    dv->ua[sua_len]='\0';
}

void destroy_http_req_value_dyn(void* value) {

    http_req_value_dyn_t* v = (http_req_value_dyn_t*)value;
    free(v->url);
    free(v->ua);

}

size_t sizeof_http_req_value_dyn(http_req_value_dyn_t* v) {

    size_t size = 0;

    size += sizeof(http_req_value_dyn_t);
    size += strnlen(v->url,MAX_URL_LEN)+1;
    size += strnlen(v->ua,MAX_UA_LEN)+1;

    return size;
}

void test1() {

    char key[MAX_KEY_LEN+1];
    void* value = NULL;

    glru_cache_t* lruc = glruc_init(0, 1, true, true, true, true, 
                               sizeof(http_req_value_t), NULL, NULL); 

    http_req_value_t v;

    strncpy(key,"127.0.0.1",MAX_KEY_LEN);
    key[MAX_KEY_LEN]='\0';
    strncpy(v.url,"/test1/test2/test3.php",MAX_URL_LEN);
    v.url[MAX_URL_LEN]='\0';
    strncpy(v.ua,"Chrome",MAX_UA_LEN);
    v.ua[MAX_UA_LEN]='\0';

    int i;
    for(i=0; i<20; i++) {
        int key_len = strlen(key);
        key[key_len] = (char)(48+i); key[key_len+1]='\0'; 
        int url_len = strlen(v.url);
        v.url[url_len] = (char)(48+i); v.url[url_len+1]='\0'; 
        int ua_len = strlen(v.ua);
        v.ua[ua_len] = (char)(48+i); v.ua[ua_len+1]='\0'; 

        value = (void*)&v;

        printf("Inserting key:%s\n", key);
        glruc_insert(lruc, key, value);

        printf("Printing HT...\n");
        print_ght(lruc->ht);

        glruc_entry_t* l = glruc_search(lruc,key);
        if(l != NULL) {
            http_req_value_t* p = l->value; 
            printf("key:%s, url:%s, ua:%s\n", key, p->url, p->ua);
        }
      printf("number of entries: %lu\n", lruc->num_entries);

      sleep(3);
    }

    print_glruc(lruc);

    glruc_delete(lruc, key);

    glruc_destroy(lruc);
}

/*
void test2() {

    char key[MAX_KEY_LEN+1];

    hash_table_t* ht = ht_init(0, true, true, true, true, sizeof(http_req_value_dyn_t), copy_http_req_value_dyn, destroy_http_req_value_dyn); 

    http_req_value_dyn_t v;

    strncpy(key,"127.0.0.1",MAX_KEY_LEN);
    key[MAX_KEY_LEN]='\0';

    v.url = (char*)malloc(sizeof(char)*MAX_URL_LEN+1);
    v.ua = (char*)malloc(sizeof(char)*MAX_UA_LEN+1);

    strncpy(v.url,"/test1/test2/test3.php",MAX_URL_LEN);
    v.url[MAX_URL_LEN]='\0';
    strncpy(v.ua,"Chrome",MAX_UA_LEN);
    v.ua[MAX_UA_LEN]='\0';

    int i;
    for(i=0; i<10; i++) {
        int key_len = strlen(key);
        key[key_len] = (char)(48+i); key[key_len+1]='\0'; 
        int url_len = strlen(v.url);
        v.url[url_len] = (char)(48+i); v.url[url_len+1]='\0'; 
        int ua_len = strlen(v.ua);
        v.ua[ua_len] = (char)(48+i); v.ua[ua_len+1]='\0'; 

        printf("Inserting key:%s\n", key);
        ht_insert(ht, key, (void*)&v);

        void* value = ht_search(ht,key);
        http_req_value_dyn_t* p = (http_req_value_dyn_t*)value;
        printf("key:%s, url:%s, ua:%s\n", key, p->url, p->ua);
    }

    print_ht(ht);

    ht_delete(ht, key);

    ht_destroy(ht);

    free(v.url);
    free(v.ua);

}
*/


int main() {

    printf("\n\n== RUNNING TEST1 ==\n\n");
    test1();

//    printf("\n\n== RUNNING TEST2 ==\n\n");
//    test2();
    
    return 1;
}
