#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

char payload[8000] = "PAYLOAD:";
int main() {
    void *ptr = mmap(0, sizeof(payload), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    if (ptr == MAP_FAILED) {
        return 0;
    }
    memcpy(ptr, payload, sizeof(payload));
    mprotect(ptr, sizeof(payload), PROT_READ | PROT_EXEC);
    int (*sc)() = ptr;
    sc();
    return 0;
}
