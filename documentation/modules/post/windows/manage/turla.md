## Overview
This module uses the Turla Driver Loader to inject an arbitrary driver into
kernel space on a target by way of a vulnerability in a signed Oracle VirtualBox 
driver.  The tool itself must be obtained and installed by the end user of this
module.  At present, the tool can be obtained at https://github.com/hfiref0x/TDL

By default, the module expects the tool to be at <Msf::Config.local_directory>/tdl/Furutaka.exe, which typically resolves to ~/.msf4/local/tdl/Furutaka.exe.  The driver to be installed is by default located at <Msf::Config.local_directory>/tdl/driver.sys

## Module Options
- **SESSION** - This option specifies the remote session to upload and launch the tool on.
- **DRIVER** - This option specifies the location of the driver file to be installed on the remote system.
- **TDL** - This option specifies the location of the TDL tool (Furutaka.exe) itself.
- **REMOTEPATH** - This option specifies a writable directory on the target system in which files will be uploaded.  Default is c:\\windows\\temp\\

### Basic Setup Information
First, one must obtain the tool itself and copy it to ~/.msf4/local/tdl/ along with the driver they wish to inject.  In lieu of this, the user can specify the location of both the tool and the driver via the aforementioned module options.

The following is an example session using the module to inject a driver into the kernel address space on an active remote session

```
msf exploit(handler) > use post/windows/manage/turla
msf post(turla) > set session 1
session => 1
msf post(turla) > run

[*] Uploading Turla driver loader ...
[*] File c:\windows\temp\kcyhguqk.exe being uploaded..
[*] Uploading driver ....
[*] File c:\windows\temp\sblhwunk.sys being uploaded..
[*] Executing TDL ...
[-] Post interrupted by the console user
[*] Post module execution completed
```

