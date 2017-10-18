/* 
 * Author: Roberto Perdisci (perdisci@cs.uga.edu)
 *
 * Testing of generic Hash Table
 */

#include <stdio.h>
#include "../../hash_table.h"

#define MAX_URL_LEN 512
#define MAX_UA_LEN 32

typedef struct http_req_value {
    char url[MAX_URL_LEN+1];
    char ua[MAX_URL_LEN+1]; // generalized user agent string
} http_req_value_t;

void destroy_http_req_value(void* value) {

    http_req_value_t* v = (http_req_value_t*)value;
    free(v->url);
    free(v->ua);

}

size_t sizeof_http_req_value(http_req_value_t* v) {

    size_t size = 0;

    size += sizeof(http_req_value_t);
    size += strnlen(v->url,MAX_URL_LEN)+1;
    size += strnlen(v->ua,MAX_UA_LEN)+1;

    return size;
}

int main(void) {


    char key[MAX_KEY_LEN+1];
    void* value = NULL;

    hash_table_t* ht = ht_init(0, 1, 1); 

    http_req_value_t v;

    strncpy(key,"127.0.0.1",MAX_KEY_LEN);
    key[MAX_KEY_LEN]='\0';
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

        value = (void*)&v;

        printf("Inserting key:%s\n", key);
        ht_insert(ht, key, value, 1, sizeof_http_req_value(&v));

        http_req_value_t* p = ht_search(ht,key);
        printf("key:%s, url:%s, ua:%s\n", key, p->url, p->ua);
    }

    print_ht(ht);

    ht_delete(ht, key);

    ht_destroy(ht);

    return 1;
}
