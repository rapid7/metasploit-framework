# Description

The Metasploit C compiler has built-in support for XOR encoding and decoding, which is implemented as the `xor.h` header.

# Code Example

```c
#include <Windows.h>
#include <String.h>
#include <xor.h>

int main(int args, char** argv) {
  char* xorStr = "NNNN";
  char xorKey = 0x0f;
  LPVOID lpBuf = VirtualAlloc(NULL, sizeof(int) * strlen(xorStr), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memset(lpBuf, '\0', strlen(xorStr));
  xor((char*) lpBuf, xorStr, xorKey, strlen(xorStr));
  MessageBox(NULL, lpBuf, "Test", MB_OK);
  return 0;
}
```

To compile, use [Metasploit::Framework::Compiler::Windows.compile_c](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Metasploit%3A%3AFramework%3A%3ACompiler%3A%3AWindows-to-compile-C-code)