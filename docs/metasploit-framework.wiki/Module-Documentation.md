You can now generate documentation for modules on the fly using the ```info -d``` command. 

Module documentation allows you to see the help for a particular module from a web page, instead of from the command line. 

The help page includes:

 - The PR history related to a particular module, if you have a [GitHub access token](https://help.github.com/articles/creating-an-access-token-for-command-line-use/) set up. 
 - The basic usage instructions for a module. 
 - The advanced usage instructions for a module, if it's available.

### How to use it
After you load a module, you can type ```info -d``` to generate a help page that provides basic usage information and displays the PR history for the module. 

```msf
msf> use auxiliary/scanner/smb/smb_login
msf (smb_login)> info -d
```

Additionally, if it's available, the help page will also include a KB that contains advanced usage information, such as vulnerable target details, caveats, and sample usage. The content in the KB is contained in a markdown file in the `metasploit-framework/documentation/modules` directory.  Its purpose is to provide supplemental information that is outside of the scope of general documentation. 


### Add an access token to see PR history

In order for you to be able to view the PR history for a module, you'll need add your GitHub access token to the environment variable `GITHUB_OAUTH_TOKEN="<your token here>"` in `.bash_profile`.

To generate a GitHub access token, check out this [page](https://help.github.com/articles/creating-an-access-token-for-command-line-use/). The token will need to have a scope for repos. 

### How you can write KBs

Generally, the person who creates the module will write the initial KB for it, but anyone can write or contribute to it. 

Before you write a KB, you should take a look at the sample template, [module_doc_template.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/module_doc_template.md), or take a look at any of the KBs that are already available. 

To write a KB, you'll need to: 

 1. Create an markdown (.md) file. 
 2. Write the content. 
 2. Save the file and name it after the module name. For example, the filename for `ms08_067_netapi.rb` is called `ms08_067_netapi.md`. 
 2. Place it in the `metasploit-framework/documentation/modules` directory as directed below.

### Where to put the KB files

If you go to `metasploit-framework/documentation/modules`, you'll see that there are documentation directories for each module type: `auxiliary`, `exploit`, `payload`, and `post`. To figure out where you need to put the file, you'll need to look at the module name.

 1. Start msfconsole.
 2. Type ```use <module name>```.
 3. Type ```info```.
 4. When the module name appears, look at the Module field. You'll see a file path for the module. That's the path where the KB needs to be added. 

For example:

```msf
msf> use auxiliary/scanner/smb/smb_login
msf (smb_login)> info

Name: SMB Login Check Scanner
Module: auxiliary/scanner/smb/smb_login
....
```

If you were creating a KB for the smb login scanner, you'd add it to ```metasploit-framework/documentation/modules/auxiliary/scanner/smb```. 

### Sections you should include in the KB

These are just suggestions, but it'd be nice if the KB had these sections:

 - **Vulnerable Applications** - Tells users what targets (version numbers) are vulnerable to the module and provides instructions on how to access vulnerable targets for testing.  If possible provide a download link and any setup instructions to configure the software appropriately.
 - **Verification Steps** - Tells users how to use the module and what the expected results are from running the module. 
 - **Options** - Provides descriptions of all the options that can be run with the module. Additionally, clearly identify the options that are required. 
 - **Scenarios** - Provides sample usage and describes caveats that the user may need to be aware of when running the module. Include the version number and OS so that this setup can be replicated at a later date.
