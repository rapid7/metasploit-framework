#include <stdio.h>
#include <string.h>

int main() {
    char ownme[256];

    memset(ownme, 'A', 280);
	printf("%s\n", ownme);
    return (0);
}
