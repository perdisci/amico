#ifdef __APPLE__

#include <string.h>

size_t strnlen(const char *s, size_t n) {
    int i;

    for(i=0; i<n; i++)
        if(s[i]=='\0')
            return i+1;

    return n;
}

#endif

