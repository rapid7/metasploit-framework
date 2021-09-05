# How to decrypt RC4 with Metasploit::Framework::Compiler

The Metasploit C compiler has built-in support for RC4 encryption and decryption, which is implemented as the `rc4.h` header.

# Code Example

```c
#include <Windows.h>
#include <rc4.h>

#define PAYLOADSIZE 12
#define RC4KEY "4ASMkFslyhwXehNZw048cF1Vh1ACzyyA"

int main(void) {
  unsigned char payload[] = "\xd8\xb0\xe9\x5a\x89\xc2\xee\x43\xb9\x30\xd0\x86";
  int lpBufSize = sizeof(int) * PAYLOADSIZE;
  LPVOID lpBuf = VirtualAlloc(NULL, lpBufSize, MEM_COMMIT, 0x04);
  memset(lpBuf, '\0', lpBufSize);
  RC4(RC4KEY, payload, (char*) lpBuf, PAYLOADSIZE);
  MessageBox(NULL, (char*) lpBuf, "Test", MB_OK);
  return 0;
}
```

To compile, use [[Metasploit::Framework::Compiler::Windows.compile_c|How to use Metasploit Framework Compiler Windows to compile C code]].