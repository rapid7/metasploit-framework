## Example Session

/tmp/hello.cs contains the following:

```
using System;

public class Hello
{
   public static void Main()
   {
      Console.WriteLine("Hello, World!");
   }
}
```

To build and run the code:

```
msf exploit(handler) > use post/windows/manage/powershell/build_net_code
msf post(build_net_code) > set session -1
session => -1
msf post(build_net_code) > show options

Module options (post/windows/manage/powershell/build_net_code):

   Name           Current Setting                                            Required  Description
   ----           ---------------                                            --------  -----------
   ASSEMBLIES     mscorlib.dll, System.dll, System.Xml.dll, System.Data.dll  no        Any assemblies outside the defaults
   CODE_PROVIDER  Microsoft.CSharp.CSharpCodeProvider                        yes       Code provider to use
   COMPILER_OPTS  /optimize                                                  no        Options to pass to compiler
   OUTPUT_TARGET                                                             no        Name and path of the generated binary, default random, omit extension
   RUN_BINARY     false                                                      no        Execute the generated binary
   SESSION        -1                                                         yes       The session to run this module on.
   SOURCE_FILE                                                               yes       Path to source code

msf post(build_net_code) > set SOURCE_FILE /tmp/hello.cs
SOURCE_FILE => /tmp/hello.cs
msf post(build_net_code) > run

[*] Building remote code.
[+] File C:\cygwin64\tmp\aNwCFmmLzlYvPWw.exe found, 3584kb
[+] Finished!
[*] Post module execution completed
msf post(build_net_code) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > shell
Process 4840 created.
Channel 7 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

E:\metasploit-framework>C:\cygwin64\tmp\aNwCFmmLzlYvPWw.exe
C:\cygwin64\tmp\aNwCFmmLzlYvPWw.exe
Hello, World!
```
