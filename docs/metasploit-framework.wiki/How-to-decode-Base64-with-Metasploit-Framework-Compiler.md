# Description

## How to decode Base64 with Metasploit::Framework::Compiler

The Metasploit C compiler has built-in support for Base64 encoding and decoding, which is implemented as `base64.h`.

# Code Example

```c
#include <Windows.h>
#include <String.h>
#include <base64.h>

// "Hello World" encoded by Rex::Text.encode_base64()
#define BASE64STR "aGVsbG8gd29ybGQ="

int main() {
  int base64StrLen = strlen(BASE64STR);
  LPVOID lpBuf = VirtualAlloc(NULL, sizeof(int) * base64StrLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memset(lpBuf, '\0', base64StrLen);
  base64decode(lpBuf, BASE64STR, base64StrLen);
  MessageBox(NULL, (char*) lpBuf, "Base64 Test", MB_OK);
  return 0;
}
```

To compile, use [[How to use Metasploit::Framework::Compiler::Windows to compile C code|How to use Metasploit Framework Compiler Windows to compile C code]]