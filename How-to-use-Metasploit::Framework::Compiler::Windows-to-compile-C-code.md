```Metasploit::Framework::Compiler::Windows``` is a wrapper of [Metasm](https://github.com/jjyg/metasm) specifically for compiling C code for the Windows platform. The purpose of the wrapper is to support default headers, such as `stdio.h`, `stdio.h`, `String.h`, `Windows.h`, or some other important headers that you might use while writing in C.

# EXE Example

```ruby
c_template = %Q|#include <Windows.h>

int main(void) {
  LPCTSTR lpMessage = "Hello World";
  LPCTSTR lpTitle = "Hi";
  MessageBox(NULL, lpMessage, lpTitle, MB_OK);
  return 0;
}|

require 'metasploit/framework/compiler/windows'

# This will save the binary in variable exe
exe = Metasploit::Framework::Compiler::Windows.compile_c(c_template)

# This will save the binary as a file
Metasploit::Framework::Compiler::Windows.compile_c_to_file('/tmp/test.exe', c_template)
```

# DLL Example

```ruby
c_template %Q|#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      MessageBox(NULL, "Hello World", "Hello", MB_OK);
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
  }

  return TRUE;
}

// This will be a function in the export table
int Msg __attribute__((export))(void) {
  MessageBox(NULL, "Hello World", "Hello", MB_OK);
  return 0;
}
|

require 'metasploit/framework/compiler/windows'
dll = Metasploit::Framework::Compiler::Windows.compile_c(c_template, :dll)
```

To load a DLL, you can use the LoadLibrary API:

```c
#include <Windows.h>
#include <stdio.h>

int main(void) {
  HMODULE hMod = LoadLibrary("hello_world.dll");
  if (hMod) {
    printf("hello_world.dll loaded\n");
  } else {
    printf("Unable to load hello_world.dll\n");
  }
}
```

Or call the function in export with rundll32:

```
rundll32 hell_world.dll,Msg
```

# Printf()

Note that methods like `printf()` won't actually print anything, because it's not hooked up to stdout. If you want to use `printf()` for debugging purposes, you can consider using `OutputDebugString`, or `MessageBox` instead.

# Custom Headers

Currently, the Metasm wrapper does not support custom headers from an arbitrary location. To work around this, you can place your headers in `data/headers/windows`, and then add that file name in `lib/metasploit/framework/compiler/headers.windows.h`.