Windows Management Instrumentation (WMI) is Microsoft's implementation of Web-Based Enterprise Management (WBEM), which uses Managed Object Format (MOF) to create Common Information Model (CIM) classes. The security community was actually unfamiliar with the evilness of this technology until the birth of Stuxnet, which used a MOF file to exploit a vulnerability allowing the attacker to create files via a fake Printer Spooler service. This technique was later reverse-engineered and demonstrated in Metasploit's ms10_061_spoolss.rb module, and that changed how we approach write-privilege attacks. Generally speaking, if you find yourself being able to write to system32, you can most likely take advantage of this technique.

### Requirements

To to able to use the WBemExec mixin, you must meet these requirements:

* Write permission to C:\Windows\System32\
* Write permission to C:\Windows\System32\Wbem\
* The target must NOT be newer than Windows Vista (so mostly good for XP, Win 2003, or older). This is more of a limitation from the API, not the technique. Newer Windows operating systems need the MOF file to be pre-compiled first.

### Usage