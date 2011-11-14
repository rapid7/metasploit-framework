# Want to get your feet wet? Start here.

Every so often, we'll get a request on the Metasploit Developer's mailing list <msfdev@metasploit.com> along the lines of, "Hey, I'm new to Metasploit, and I want to help!" The usual answer is something like, "Great! Here's our [most wanted vulnerability list](https://dev.metasploit.com/redmine/projects/framework/wiki/Exploit_Todo), and here's our [framework bug tracker](https://dev.metasploit.com/redmine/projects/framework/issues), get crackin!"

However, tackling core Metasploit Framework bugs or particularly squirrelly exploits probably isn't the right place for the newbie. Believe me, everyone was a newbie once, there's no shame in that. Those bugs and vulns are usually complicated, nuanced, and there's so many to choose from, it's hard to get started.

This page will attempt to keep a very short list of relatively straightforward, older exploits. For whatever reason, they haven't quite made it into the framework yet. As these modules get written and committed, new ones will take their place, so don't worry too much about duplicating effort.

## Server Exploits

### [CVE-2005-0058](http://www.cvedetails.com/cve/CVE-2005-0058)

**Description:** Buffer overflow in the Telephony Application Programming Interface (TAPI) for Microsoft Windows 98, Windows 98 SE, Windows ME, Windows 2000, Windows XP, and Windows Server 2003 allows attackers elevate privileges or execute arbitrary code via a crafted message.
**Affected Software:** Microsoft Windows 2000, 2003, and XP
**Module Type:** exploits/windows/dcerpc
**Proof of concept:** http://www.securiteam.com/exploits/5VP0D1FI0Y.html

### [CVE-2008-2161](http://www.cvedetails.com/cve/CVE-2008-2161)

**Description:** Buffer overflow in TFTP Server SP 1.4 and 1.5 on Windows, and possibly other versions, allows remote attackers to execute arbitrary code via a long TFTP error packet. 
**Affected Software:** [Open TFTP Server](http://sourceforge.net/scm/?type=cvs&group_id=162512), versions 1.4 and 1.5
**Module Type:** exploits/windows/tftp (perhaps multi/tftp as it's cross-platform)
**Proof of concept:** http://downloads.securityfocus.com/vulnerabilities/exploits/29111.pl

### [CVE-2004-2111](http://www.cvedetails.com/cve/CVE-2004-2111)

**Description:** Stack-based buffer overflow in the site chmod command in Serv-U FTP Server before 4.2 allows remote attackers to execute arbitrary code via a long filename.
**Affected Software:** [RhinoSoft Serv-U FTP Server](http://www.serv-u.com/) pre-4.1.0.3
**Module Type:** exploits/windows/ftp
**Proof of concept:** http://www.securityfocus.com/bid/9483/exploit

## Client Exploits

### [CVE-2005-1790](http://www.cvedetails.com/cve/CVE-2005-1790)

**Description:** Microsoft Internet Explorer 6 SP2 6.0.2900.2180 and 6.0.2800.1106, and earlier versions, allows remote attackers to cause a denial of service (crash) and execute arbitrary code via a Javascript BODY onload event that calls the window function, aka "Mismatched Document Object Model Objects Memory Corruption Vulnerability."
**Affected Software:** Microsoft Internet Explorer 6, SP2
**Module Type:** exploits/windows/browser
**Proof of concept:** http://www.securityfocus.com/bid/13799/exploit

### [CVE-2008-5499](http://www.cvedetails.com/cve/CVE-2008-5499)

**Description:** Unspecified vulnerability in Adobe Flash Player for Linux 10.0.12.36, and 9.0.151.0 and earlier, allows remote attackers to execute arbitrary code via a crafted SWF file.
**Affected Software:** Adobe Flash Player for Linux, version 10.0.12.36 and 9.0.151.0 and prior (give http://kb2.adobe.com/cps/142/tn_14266.html a try)
**Module Type:** exploits/linux/browser
**Proof of concept:** http://www.securityfocus.com/bid/32896/exploit

## The Usual Warnings

You probably shouldn't run proof of concept exploit code you find on the Internet on a machine you care about in a network you care about. That is generally considered a Bad Idea. You also probably shouldn't use your usual computer as a target for exploit development, since you are intentionally inducing unstable behavior.

If you intend to submit your shiny new modules for old crusty bugs to Metasploit, please take a peek at our guides on using git, and our acceptance guidelines for new modules, here: https://github.com/rapid7/metasploit-framework/wiki

If you get stuck, try to explain your specific problem as best you can on our Freenode IRC channel, #metasploit, and someone should be able to lend a hand. Apparently, some of those people never sleep.

## Thank you

In case nobody's said it yet: Thanks for your interest and support! Exploit developers from the open source community are the soul of Metasploit, and by contributing your time and talent, you are helping advance the state of the art for intelligent IT defense. We simply couldn't do all of this without you.
