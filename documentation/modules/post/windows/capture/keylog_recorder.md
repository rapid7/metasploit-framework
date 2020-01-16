## Overview

This module captures keystrokes from a Windows target and saves them to a text file in loot. Keystrokes can be captured from explorer.exe, winlogon.exe, or a specific process of your choice. The module is capable of being run as a job to keep the Framework's user interface available for other tasks.

## Requirements
- Windows Meterpreter Session

## Options
- **CAPTURE_TYPE** - This option sets the process where the module records keystrokes. Accepted: explorer, winlogon, or pid. Default value is explorer.

- **INTERVAL** - The interval in seconds that the module uses for recording keystrokes. The log file goes to a new line at the end of each interval. Default value is 5 seconds.

- **LOCKSCREEN** - This option locks the screen of the target when set to TRUE. CAPTURE_TYPE must be set to winlogon. MIGRATE must be set to TRUE or the session must already be in winlogon.exe. Defalt value is FALSE.

- **MIGRATE** - This option migrates the session based on the CAPTURE_TYPE. Explorer.exe for explorer, winlogon.exe for winlogon, or a specified PID for pid. Default value is FALSE.

- **PID** - The PID of a process to migrate the session into. CAPTURE_TYPE of pid must be set, and the sepecified PID must exist on the target machine.

- **SESSION** - The session to run the module on.

### Advanced Options
- **ShowKeystrokes** - This option prints the captured keystrokes to the Framework UI on the specified interval. Default is FALSE.
- **TimeOutAction** - This option sets the behavior the module takes if the key capture request times out. (See below.) Accepted: wait or exit. Default value is wait.

## Usage
The Meterpreter session must be located in an appropriate process for keystroke recording to work properly. This is described in the below-listed capture types. This module can migrate the session if MIGRATE is set to TRUE. If winlogon or PID migration fails, the module will exit. Set MIGRATE to FALSE if migration will be performed manually or through another module. 

### Capture Types
- **Explorer.exe** - __Session must be in explorer.exe__ - The most common capture type. Keystrokes are recorded from most user level applications. Applications running at an elevated level will likely not get recorded. **NOTE: Sessions running with elevated privileges are downgraded to user level when migrated into explorer.exe.** It is recommended that a second session be opened for keystroke recording if elevated priveledges are to be maintained.

- **Winlogon.exe** - __Session must be in winlogon.exe__ - Administrator or SYSTEM rights are required to migrate to winlogon.exe. Keylogging from this process records usernames and passwords as users log in. This capture type does not record keystrokes from any other process. Setting LOCKSCREEN to true locks Windows when the module is executed. This forces the user to unlock the computer, and their password is captured.

- **PID** - __Session must be in the specific process to be recorded.__ - This option is useful for recording keystrokes in applications or process that run with elevated priveledges. However, admin or SYSTEM rights are required to migrate to these processes. Only keystrokes from the specified process are recorded.

## Running Module as a Job
It is recommended to run this module as a job using: `exploit -j` or `run -j`. As a job, the module runs in the background preventing it from tying up the Framework's user interface. To stop capturing keystrokes, kill the job using `jobs -k`. The module records the last few keystrokes before exit. Stopping the job can take up to 30 seconds. If the session is killed, the key log job shuts down automatically.

### TimeOutAction
This module has two actions it can take if module requests time out. This occurs with packet-based payloads like `reverse_http` or `reverse_https` when the target system stops responding to requests for a specific period of time. The default is 300 seconds. Sessions can stop responding due to various events such as network problems, system shut down, system sleep, or user log off.

- **WAIT** - With this option selected, the module suspends attempting to gather keystrokes after the timeout. It waits for the session to become active again, then resumes capturing keystrokes. The output log reflects that recording was suspended along with a timestamp. If the session becomes active again, the log indicates this along with a timestamp. The wait option allows keystrokes to be logged over multiple system sleep cycles. In the event that the session dies, the recording job is stopped automatically.

- **EXIT** - With this option selected, the module exits and the job is killed when the timeout occurs. The output log reflects the exit along with a timestamp.

### Running Module Stand Alone
When running the module stand alone, it will prevent the Framework UI from being use for anything else until you exit the module. Use `CTRL-C` to exit. The module will save the last few keystrokes. This may take up to 30 seconds to complete.

## Example Output
```
Keystroke log from explorer.exe on JULY with user JULY\User started at 2016-07-13 21:01:56 -0500

This is an ex
ample output from keylog_recorder.
 <Return>  <Return> On this line I make a typpor <Back>  <Back>  <Back> 
o. <Return> 
 <Return> Username <Tab> Password <Return> 
 <Return> 
 <N1>  <N9>  <N2>  <Decimal>  <N1>  <N6>  <N8>  <Decimal>  <N1>  <Decimal>  <N1>  <N0>  <N0>  <Return> 
 Copy <Left>  <Left>  <Left>  <Left>  <Ctrl>  <LCtrl> c <Right>  <Right>  <Right>  <Right>  <Return>  <Return>  <Ctrl>  <LCtrl> v <Return>  <Return> 

Keylog Recorder timed out - now waiting at 2016-07-13 21:09:33 -0500


Keylog Recorder resumed at 2016-07-13 21:11:36 -0500

 <Return> T
his is keys logged after the computer
 was put to sleep and then woken back up.
 <Return> 

Keylog Recorder exited at 2016-07-13 21:12:44 -0500
```




