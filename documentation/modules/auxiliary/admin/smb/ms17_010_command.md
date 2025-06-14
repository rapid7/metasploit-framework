## Introduction

MS17-010 and psexec are two of the most popular exploits against Microsoft Windows. This module bolts the two together.

You can run any command as SYSTEM. Note: unlike EternalBlue, kernel shellcode is not used to stage Meterpreter, so you might have to evade your payloads.

* CVE-2017-0146 (EternalChampion/EternalSynergy) - exploit a race condition with Transaction requests
* CVE-2017-0143 (EternalRomance/EternalSynergy) - exploit a type confusion between WriteAndX and Transaction requests

This module is highly reliable and preferred over EternalBlue where a Named Pipe is accessible for anonymous logins (generally, everything pre-Vista, and relatively common for domain computers in the wild).

## Vulnerable Server

To be able to use auxiliary/admin/smb/ms17_010_command:

1. You can OPTIONALLY use a valid username/password to bypass most of these requirements.
2. The firewall must allow SMB traffic.
3. The target must use SMBv1.
4. The target must be missing the MS17-010 patch.
5. The target must allow anonymous IPC$ and a Named Pipe.

You can check all of these with the SMB MS17-010 and Pipe Auditor auxiliary scanner modules.

If you're having trouble configuring an anonymous named pipe,
Microsoft's
[documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously)
on the topic may be helpful.

## Verification Steps

At the minimum, you should be able use psexec to get a session with a valid credential using the following:

```
msf > use auxiliary/admin/smb/ms17_010_command
msf exploit(psexec) > set RHOSTS 192.168.1.80
RHOSTS => 192.168.1.80
msf exploit(psexec) > exploit
```

## Options

By default, using auxiliary/admin/smb/ms17_010_command can be as simple as setting the RHOSTS option, and you're ready to go.

**The NAMEDPIPE Option**

By default, the module will scan for a list of common pipes for any available one. You can specify one by name.

**The LEAKATTEMPTS Option**

Information leaks are used to ensure stability of the exploit. Sometimes they don't pop on the first try.

**The DBGTRACE Option**

Used to debug, gives extremely verbose information.

**The SMBUser Option**

This is a valid Windows username.

**The SMBPass option**

This can be either the plain text version or the Windows hash.

## Scenarios

**Automatic Target**

There are multiple targets available for exploit/windows/smb/psexec. The Automatic target is the default target. If the  Automatic target detects Powershell on the remote machine, it will try Powershell, otherwise it uses the natvie upload. Each target is explained below.

**Powershell Target**

The Powershell target forces the psexec module to run a Powershell command with a payload embedded in it. Since this approach does not leave anything on disk, it is a very powerful way to evade antivirus. However, older Windows machines might not support Powershell by default.

Because of this, you will probably want to use the Automatic target setting. The automatic mode will check if the target supports Powershell before it tries it; the manually set Powershell target won't do that.

**Native Upload Target**

The Native target will attempt to upload the payload (executable) to SYSTEM32 (which can be modified with the
SHARE datastore option), and then execute it with psexec.

This approach is generally reliable, but has a high chance of getting caught by antivirus on the target. To counter this, you can try to use a template by setting the EXE::Path and EXE::Template datastore options. Or, you can supply your own custom EXE by setting the EXE::Custom option.

**MOF Upload Target**

The [MOF](https://docs.metasploit.com/docs/development/developing-modules/libraries/how-to-use-wbemexec-for-a-write-privilege-attack-on-windows.html) target technically does not use psexec; it does not explicitly tell Windows to execute anything. All it does is upload two files: the payload (exe) in SYSTEM32 and a managed object
format file in SYSTEM32\wbem\mof\ directory. When Windows sees the MOF file in that directory, it automatically runs it. Once executed, the code inside the MOF file basically tells Windows to execute our payload in SYSTEM32, and you get a session.

Although it's a neat trick, Metasploit's MOF library only works against Windows XP and Windows Server 2003. And since it writes files to disk, there is also a high chance of getting
caught by antivirus on the target.

The best way to counter antivirus is still the same. You can either use a different template by setting the EXE::Path and EXE::Template datastore options or you can supply your own custom EXE by setting the EXE::Custom option.
