#include <stdlib.h>
#include "../msfpattern.h"

int main() {
    char ownme[256];

    msf_pattern_create(500, ownme);
    printf("%s\n", ownme);
    return (0);
}
