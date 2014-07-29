Windows Management Instrumentation (WMI) is Microsoft's implementation of Web-Based Enterprise Management (WBEM), which uses Managed Object Format (MOF) to create Common Information Model (CIM) classes. The security community was actually unfamiliar with the evilness of this technology until the birth of Stuxnet, which used a MOF file to exploit a vulnerability allowing the attacker to create files via a fake Printer Spooler service. This technique was later reverse-engineered and demonstrated in Metasploit's ms10_061_spoolss.rb module, and that changed how we approach write-only attacks.

### Requirements

To to able to use the WBemExec mixin, you must meet these requirements:

* Being able to write a file to C:\Windows\System32\
* Being able to write a file to C:\Windows\System32\Wbem\

