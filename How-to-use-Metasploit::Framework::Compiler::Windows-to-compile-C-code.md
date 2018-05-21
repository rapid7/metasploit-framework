```Metasploit::Framework::Compiler::Windows``` is a wrapper of [Metasm](https://github.com/jjyg/metasm) specifically for compiling C code for the Windows platform. The purpose of the wrapper is to support default headers, such as `stdio.h`, `stdio.h`, `String.h`, `Windows.h`, or some other important headers that you might use while writing in C.

# Example

```c
#include <Windows.h>

int main(void) {
  LPCTSTR lpMessage = "Hello World";
  LPCTSTR lpTitle = "Hi";
  MessageBox(NULL, lpMessage, lpTitle, MB_OK);
  return 0;
}
```

# Printf()

Note that methods like `printf()` won't actually print anything, because it's not hooked up to stdout. If you want to use `printf()` for debugging purposes, you can consider using `OutputDebugString`, or `MessageBox` instead.

# Custom Headers

Currently, the Metasm wrapper does not support custom headers from an arbitrary location. To work around this, you can place your headers in `data/headers/windows`, and then add that file name in `lib/metasploit/framework/compiler/headers.windows.h`.