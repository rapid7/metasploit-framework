Adding and reviewing module documentation is a great way to contribute to the Metasploit Framework. 

Before you write any module documentation, you should take a look at the sample template, [module_doc_template.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/module_doc_template.md), or take a look at any of the KBs that are already available.

### Writing a KB

To write a KB, you'll need to:

* Create a markdown (.md) file.
* Write the content.
* Save the file and name it after the module name. For example, the filename for ms08-067 is `modules/exploits/windows/smb/ms08_067_netapi.rb`, so its documentation is `documentation/modules/exploits/windows/smb/ms08_067_netapi.md`.
* Place it in the metasploit-framework/documentation/modules directory.

### Where to put the markdown files

If you go to metasploit-framework/documentation/modules, you'll see that there are documentation directories for each module type: auxiliary, exploit, payload, and post. To figure out where you need to put the file, you'll need to look at the module's path. 

 1. Start msfconsole.
 2. Type `use <module name>`.
 3. Type `info -d`.
 4. When the module name appears, look at the Module field. You'll see a file path for the module. That's the path where the KB needs to be added. 

For example:

```msf
msf> use auxiliary/scanner/smb/smb_login
msf (smb_login)> info

Name: SMB Login Check Scanner
Module: auxiliary/scanner/smb/smb_login
....
```

If you were creating a KB for the smb login scanner, you'd add it to `metasploit-framework/documentation/modules/auxiliary/smb.md`. 

### Sections you should include in the KB

These are just suggestions, but it'd be nice if the KB had these sections:

 - **Vulnerable Applications** - Tells users what targets are vulnerable to the module and provides instructions on how to access vulnerable targets for testing.  
 - **Verification Steps** - Tells users how to use the module and what the expected results are from running the module. 
 - **Options** - Provides descriptions of all the options that can be run with the module. Additionally, clearly identify the options that are required. 
 - **Scenarios** - Provides sample usage and describes caveats that the user may need to be aware of when running the module.

### Before you submit your PR: msftidy_docs.rb

A documentation file can be passed as a positional argument to `metasploit-framework/tools/dev/msftidy_docs.rb` and will
highlight formatting errors the docs file might contain. Once all the errors and warnings thrown by `msftidy_docs.rb` have
been resolved, the documentation file is ready for submission.

```
➜  metasploit-framework git:(upstream-master) ✗ ruby tools/dev/msftidy_docs.rb documentation/modules/exploit/linux/http/panos_op_cmd_exec.md
documentation/modules/exploit/linux/http/panos_op_cmd_exec.md - [INFO] Missing Section: ## Options
documentation/modules/exploit/linux/http/panos_op_cmd_exec.md - [WARNING] Please add a newline at the end of the file
documentation/modules/exploit/linux/http/panos_op_cmd_exec.md - [WARNING] H2 headings in incorrect order. Should be: Vulnerable Application, Verification Steps/Module usage, Options, Scenarios
documentation/modules/exploit/linux/http/panos_op_cmd_exec.md:50 - [WARNING] Should use single backquotes (`) for single line literals instead of triple backquotes (```)
documentation/modules/exploit/linux/http/panos_op_cmd_exec.md:53 - [WARNING] Spaces at EOL
```