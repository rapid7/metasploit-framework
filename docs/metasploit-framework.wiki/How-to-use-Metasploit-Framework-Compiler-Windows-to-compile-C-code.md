
## On this page

* [EXE Example](#exe-example)
* [DLL Example](#dll-example)
* [Printf()](#printf)
* [Custom Headers](#custom-headers)
* [Code Randomization](#code-randomization)

```Metasploit::Framework::Compiler::Windows``` is a wrapper of [Metasm](https://github.com/jjyg/metasm) specifically for compiling C code for the Windows platform. The purpose of the wrapper is to support default headers, such as `stdio.h`, `stdio.h`, `String.h`, `Windows.h`, or some other important headers that you might use while writing in C.

## EXE example

```ruby
c_template = %Q|#include <Windows.h>

int main(void) {
  LPCTSTR lpMessage = "Hello World";
  LPCTSTR lpTitle = "Hi";
  MessageBox(NULL, lpMessage, lpTitle, MB_OK);
  return 0;
}|

require 'metasploit/framework/compiler/windows'


## Save as an exe variable
exe = Metasploit::Framework::Compiler::Windows.compile_c(c_template)

## Save the binary as a file
Metasploit::Framework::Compiler::Windows.compile_c_to_file('/tmp/test.exe', c_template)
```

## DLL example

```ruby
c_template = %Q|#include <Windows.h>

BOOL APIENTRY DllMain __attribute__((export))(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
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

## Printf()

Methods like `printf()` won't actually print anything, because it's not connected up to stdout. If you want to use `printf()` for debugging purposes, consider using `OutputDebugString`, or `MessageBox`.

## Custom Headers

Currently, the Metasm wrapper does not support custom headers from an arbitrary location. To work around this, you can place your headers in `data/headers/windows`, and then add that file name in `lib/metasploit/framework/compiler/headers/windows.h`.

## Code Randomization

`Metasploit::Framework::Compiler` supports obfuscation that randomizes code at the source code level, and then compile. There are two methods we can use:
 
* `Metasploit::Framework::Compiler::Windows.compile_random_c`
* `Metasploit::Framework::Compiler::Windows.compile_random_c_to_file`

Metasploit::Framework::Compiler::Windows.compile_random_c_to_file example:

```ruby
require 'msf/core'
require 'metasploit/framework/compiler/windows'

c_source_code = %Q|
#include <Windows.h>

int main() {
  const char* content = "Hello World";
  const char* title = "Hi";
  MessageBox(0, content, title, MB_OK);
  return 0;
}|

outfile = "/tmp/helloworld.exe"
weight = 70 # This value is used to determine how random the code gets.
Metasploit::Framework::Compiler::Windows.compile_random_c_to_file(outfile, c_source_code, weight: weight)
```
