Metasploit Framework 6.0 is in progress!

Metasploit 6.0 adds a number of features and promotes a theme of being "secure by default".

See the release initial announcement [here](https://blog.rapid7.com/2020/08/06/xyz).

## Pull Requests

A complete list of pull requests included as part of the initial version 6 work:

* Meterpreter Improvements
    * Add AES TLV encryption support: [Java](https://github.com/rapid7/metasploit-payloads/pull/400), [Python](https://github.com/rapid7/metasploit-framework/pull/13432)
        * Support AES-128-CBC as an additional option: [Framework Core](https://github.com/rapid7/metasploit-framework/pull/13783), [Java](https://github.com/rapid7/metasploit-payloads/pull/418)
        * Change from PEM to DER for crypt TLV negotiation: [Windows, Java, PHP](https://github.com/rapid7/metasploit-payloads/pull/397), [Framework Core](https://github.com/rapid7/metasploit-framework/pull/13400), [mettle](https://github.com/rapid7/mettle/pull/197), [Python](https://github.com/rapid7/metasploit-payloads/pull/415)
    * Remove DLL exports from Meterpreter: [Windows](https://github.com/rapid7/metasploit-payloads/pull/401) [Framework Core](https://github.com/rapid7/metasploit-framework/pull/13476), [ReflectiveDLLInjection](https://github.com/rapid7/ReflectiveDLLInjection/pull/9)
    * Replace METHOD string with COMMAND_ID integer (to remove obvious strings): [Framework Core](https://github.com/rapid7/metasploit-framework/pull/13395), [Windows, Java, PHP, Python](https://github.com/rapid7/metasploit-payloads/pull/395)
    * [Cross-compile Windows binaries on Linux](https://github.com/rapid7/metasploit-payloads/pull/405)
        * [Various changes required for cross compilation](https://github.com/rapid7/mimikatz/pull/4)
        * [Update readme for cross compilation](https://github.com/rapid7/metasploit-payloads/pull/419)
    * Remove the old Mimikatz extension: [Windows](https://github.com/rapid7/metasploit-payloads/pull/404), [Framework Core](https://github.com/rapid7/metasploit-framework/pull/13529)
* Add SMBv3 support: [ruby_smb](https://github.com/rapid7/ruby_smb/pull/154), [Framework Core](https://github.com/rapid7/metasploit-framework/pull/13417)
    * [Fixes and improvements from MSF code review](https://github.com/rapid7/ruby_smb/pull/156)
    * [Store server system and start time values](https://github.com/rapid7/ruby_smb/pull/155)
* [Add a command target to the PSexec module](https://github.com/rapid7/metasploit-framework/pull/13812)
* [Polymorphic x86/x64 Block API](https://github.com/rapid7/metasploit-framework/pull/13832)

## Get Metasploit 6.0

You can get Metasploit 6.0 by checking out the [6.0.0 tag](https://github.com/rapid7/metasploit-framework/releases/tag/6.0.0) in the Metasploit GitHub project.

Need a primer on Framework architecture and usage? Take a look at [our wiki here](https://github.com/rapid7/metasploit-framework/wiki), and feel free to reach out to the broader community [on Slack](https://metasploit.com/slack). There are also myriad public and user-generated resources on Metasploit tips, tricks, and content, so if you can’t find something you want in our wiki, ask Google or the community what they recommend. 

See all the ways to stay informed and get involved at https://metasploit.com.