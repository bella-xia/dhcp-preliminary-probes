#include "kstring.h"


int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) 
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++)
        len++;
    return len;
}

char *strcpy(char *dst, const char *src) {
    char *ret = dst;
    while ((*dst++ = *src++));
    return ret;
}

char *strncpy(char *dst, const char *src, size_t n) {
    char *ret = dst;
    size_t i;
    for (i = 0; i < n && *src != '\0'; i++)
        *dst = *src++;
    for (; i < n; i++) 
        *dst++ = '\0';
    return ret;
}
