#define DEBUG 0

#include <stdlib.h>
#include <memory.h>

#if DEBUG
#include <stdio.h>
#endif

void msf_pattern_create(int length, char *patternStr) {
    char upper      = 'A';
    char lower      = 'a';
    char num        = '0';
    char c;
    unsigned int i  = 0;

    while (i != length) {
        switch (i%3) {
            case 0:
                c = upper;
                break;
            case 1:
                c = lower;
                break;
            case 2:
                c = num;
                if (num++ == '9') {
                    num = '0';
                    if (lower++ == 'z') {
                        lower = 'a';
                        if (upper++ == 'Z') {
                            upper = 'A';
                        }
                    }
                }
                break;
        }
        patternStr[i] = c;
        i++;
    }
}

int msf_pattern_offset(int length, unsigned int needle) {
    char            *patternStr;
    unsigned int    *haystack;

    if (length < 4)
        return (-1);

    patternStr =  (char *) malloc(length+1);
    if (patternStr == NULL) {
        return (-1);
    }
    memset(patternStr, 0x00, length+1);

    msf_pattern_create(length, patternStr);
    
    length -= 4;
    while (length >= 0) {
        haystack = (unsigned int *) &patternStr[length];
        //printf("Haystack: 0x%08x\n", *haystack);
        if (needle == *haystack)
            break;
        length--;
    }

    free(patternStr);
    return (length);
}

#if DEBUG
int main() {
    char pattern[256];
    char findme[] = "0Aa1";

    memset(pattern, 0x00, 256);
    msf_pattern_create(255, pattern);

    printf("Pattern: %s\n", pattern);
    printf("%s @ %d\n", findme, msf_pattern_offset(255, findme));
    return (0);
}
#endif
