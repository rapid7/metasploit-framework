# Want to get your feet wet? Start here.

Every so often, we'll get a request on the Metasploit Developer's mailing list, <msfdev@metasploit.com>, along the lines of, "Hey, I'm new to Metasploit, and I want to help!" The usual answer is something like, "Great! Here's our [most wanted vulnerability list](https://dev.metasploit.com/redmine/projects/framework/wiki/Exploit_Todo), and here's our [framework bug tracker](https://dev.metasploit.com/redmine/projects/framework/issues), get crackin!"

However, tackling core Metasploit Framework bugs or particularly squirrelly exploits probably isn't the right place for the newbie. Believe me, everyone was a newbie once, there's no shame in that. Those bugs and vulns are usually complicated, nuanced, and there's so many to choose from, it's hard to get started.

This page will attempt to keep a very short list of relatively straightforward, older vulnerabilities to cut your teeth on. For whatever reason, they haven't quite made it into the framework yet, but they are real, and we really do want them.

As modules for these vulnerabilities get written and committed, new ones will take their place, so don't worry too much about duplicating effort. This list should stay pretty fresh no matter when you happen to look at it.

## Server exploits

Server exploits are "classic" exploits -- the target is a network service on a remote server.

### [CVE-2006-5276](http://www.cvedetails.com/cve/CVE-2006-5276)

**Description:** A buffer overflow in the Snort IDS DCE/RPC Reassembly preprocessor can allow remote code execution in the context of the Snort service.

**Affected Software:** [Snort v2.6.1](http://cvs.snort.org/viewcvs.cgi/snort/?only_with_tag=SNORT_v2_6_1), SourceFire IDS versions 4.1, 4.5, and 4.6
**Module Type:** exploits/linux/ids

**Proof of concept:** http://downloads.securityfocus.com/vulnerabilities/exploits/22616-linux.py

## Client Exploits

Client exploits generally run as an "evil service" that a remote client will connect to. They nearly always require some kind of user interaction to trigger, such a viewing a web page, downloading a file, or otherwise connecting to the service controlled by the attacker.

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

### [CVE-2009-0388](http://www.cvedetails.com/cve/CVE-2009-0388)

**Description:** Multiple signed integer bugs in both UltraVNC and TightVNC clients can allow malicious VNC servers to execute arbitrary code on a victim's client system.

**Affected Software:** [UltraVNC](http://ultravnc.svn.sourceforge.net/viewvc/ultravnc/) version 1.0.2, [TightVNC](http://download.cnet.com/TightVNC/3000-7240_4-10739369.html) version 1.3.9

**Module Type:** exploits/windows/vnc

**Proof of concept:** http://downloads.securityfocus.com/vulnerabilities/exploits/33568-desi.py

## Privilege Escalation Exploits

Privilege escalation exploits tend to require the attacker already have an account on a target computer. They are nearly always going to be implemented as Metasploit post modules.

### [CVE-2005-0058](http://www.cvedetails.com/cve/CVE-2005-0058)

**Description:** Buffer overflow in the Telephony Application Programming Interface (TAPI) for Microsoft Windows 98, Windows 98 SE, Windows ME, Windows 2000, Windows XP, and Windows Server 2003 allows attackers elevate privileges or execute arbitrary code via a crafted message.

**Affected Software:** Microsoft Windows 2000, 2003, and XP

**Module Type:** exploits/windows/dcerpc

**Proof of concept:** http://www.exploit-db.com/exploits/1584/



## The Usual Warnings

You probably shouldn't run proof of concept exploit code you find on the Internet on a machine you care about in a network you care about. That is generally considered a Bad Idea. You also probably shouldn't use your usual computer as a target for exploit development, since you are intentionally inducing unstable behavior.

If you intend to submit your shiny new modules for old crusty bugs to Metasploit, please take a peek at our guides on using git, and our acceptance guidelines for new modules, here: https://github.com/rapid7/metasploit-framework/wiki

If you get stuck, try to explain your specific problem as best you can on our Freenode IRC channel, #metasploit, and someone should be able to lend a hand. Apparently, some of those people never sleep.

## Thank you

In case nobody's said it yet: Thanks for your interest and support! Exploit developers from the open source community are the soul of Metasploit, and by contributing your time and talent, you are helping advance the state of the art for intelligent IT defense. We simply couldn't do all of this without you.
