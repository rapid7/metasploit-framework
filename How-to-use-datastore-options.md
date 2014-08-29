A datastore option is a type of variable that can be set by the user, allowing various components of Metasploit to be more configurable during use. For example, in msfconsole, you can set the ConsoleLogging option in order to log all the console input/output - something that's kind of handy for documentation purposes during a pentest. When you load a module, there will be a lot more options registered by the mixin(s) or the module. Some common ones include: RHOST and RPORT for a server-side exploit or auxiliary module, SRVHOST for a client-side module, etc. The best way to find out exactly what datastore options you can set is by using these commands:

* ```show options``` - Shows you all the basic options.
* ```show advanced``` - Shows you all the advanced options.
* ```set``` - Shows you everything. Obviously you also use this command to set an option.

### ModuleDataStore options vs session options vs framework options

How users look at datastore options:

On the user's side, datastore options are seen as global or module-level: Global means all the modules can use that option, which can be set by using the ```setg``` command. Module-level means only that particular module you're using remembers that datastore option, no other components will know about it. You are setting a module-level option if you load a module first, and then use the ```set``` command.

How Metasploit developers look at datastore options:

On the development side, things are a little crazier. Datastore options actually can be found in at least three different sources: the ModuleDataStore object, session object, or the framework object.

If you're just doing module development, almost all the time all you care is datastore options from the ModuleDataStore object. The ModuleDataStore object has a specific load order before handing you the option you want: if the option can be found in the module's datastore, it will give you that. If not found, it will give you the one from framework. The following is an example of how to read a datastore option in a module:

```ruby
current_host = datastore['RHOST']
```

If your dev work is outside the module realm, there is a good possibility you don't even have the ModuleDataStore object. But in some cases, you still might have a module object. A module object is usually created this way:

```ruby
# Returns Msf::Modules::Mod[hash]::Metasploit3
framework.modules.create("exploits/windows/smb/ms08_067_netapi")
```

If you have this object, there should be a ```#datastore``` method:

```
>> mod.datastore
=> {"EXITFUNC"=>"thread", "VERBOSE"=>"false", "WfsDelay"=>"0", "EnableContextEncoding"=>"false", "DisablePayloadHandler"=>"false", "SSL"=>"false", "SSLVersion"=>"SSL3", "SSLVerifyMode"=>"PEER", "ConnectTimeout"=>"10", "TCP::max_send_size"=>"0", "TCP::send_delay"=>"0", "DCERPC::max_frag_size"=>"4096", "DCERPC::fake_bind_multi"=>"true", "DCERPC::fake_bind_multi_prepend"=>"0", "DCERPC::fake_bind_multi_append"=>"0", "DCERPC::smb_pipeio"=>"rw", "RPORT"=>"445", "DCERPC::ReadTimeout"=>"10", "NTLM::UseNTLMv2"=>"true", "NTLM::UseNTLM2_session"=>"true", "NTLM::SendLM"=>"true", "NTLM::UseLMKey"=>"false", "NTLM::SendNTLM"=>"true", "NTLM::SendSPN"=>"true", "SMB::pipe_evasion"=>"false", "SMB::pipe_write_min_size"=>"1", "SMB::pipe_write_max_size"=>"1024", "SMB::pipe_read_min_size"=>"1", "SMB::pipe_read_max_size"=>"1024", "SMB::pad_data_level"=>"0", "SMB::pad_file_level"=>"0", "SMB::obscure_trans_pipe_level"=>"0", "SMBDirect"=>"true", "SMBUser"=>"", "SMBPass"=>"", "SMBDomain"=>".", "SMBName"=>"*SMBSERVER", "SMB::VerifySignature"=>"false", "SMB::ChunkSize"=>"500", "SMB::Native_OS"=>"Windows 2000 2195", "SMB::Native_LM"=>"Windows 2000 5.0", "SMBPIPE"=>"BROWSER"}
```


### Basic vs advanced options

### Types of options

### The register_options method

### The deregister_options method

### Modifying datastore options at run-time