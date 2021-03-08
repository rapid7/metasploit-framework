Start here:

* https://tryhackme.com/room/rpmetasploit
* http://www.offensive-security.com/metasploit-unleashed/Main_Page (slightly outdated now in some areas, but still contains a lot of good info)
* https://metasploit.help.rapid7.com/docs/
* https://www.kali.org/docs/tools/starting-metasploit-framework-in-kali/
* https://github.com/rapid7/metasploitable3
* [[Evading Anti-Virus]]

Database troubleshooting
------------------------
If the database is not connecting automatically, first make sure it is running:
* Linux:`$ netstat -lnt | grep 7337` where 7337 is whatever port you told it to listen on during installation
* Windows: look for a postgres.exe process in task manager.

If postgres is not running, try starting it manually:
* Linux:`$ sudo /etc/init.d/metasploit start` or if you didn't choose to install as a service: `$ sudo /opt/metasploit*/ctlscript.sh start`
* Windows: Start -> Metasploit -> Services -> Start Services

Once postgres is running and listening, go back to msfconsole:

```
msf > db_connect
```
