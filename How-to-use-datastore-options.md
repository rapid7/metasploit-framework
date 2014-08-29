A datastore option is a type of variable that can be set by the user, allowing various components of Metasploit to be more configurable during use. For example, in msfconsole, you can set the ConsoleLogging option in order to log all the console input/output - something that's kind of handy for documentation purposes during a pentest. When you load a module, there will be a lot more options registered by the mixin(s) or the module. Some common ones include: RHOST and RPORT for a server-side exploit or auxiliary module, SRVHOST for a client-side module, etc. The best way to find out exactly what datastore options you can set is by using these commands:

* ```show options``` - Shows you all the basic options.
* ```show advanced``` - Shows you all the advanced options.
* ```set``` - Shows you everything. Obviously you also use this command to set an option.

### Option sources: ModuleDataStore, active_module, session, and framework

**How users look at datastore options:**

On the user's side, datastore options are seen as global or module-level: Global means all the modules can use that option, which can be set by using the ```setg``` command. Module-level means only that particular module you're using remembers that datastore option, no other components will know about it. You are setting a module-level option if you load a module first, and then use the ```set``` command, like the following:

```
msf > use exploit/windows/smb/ms08_067_netapi 
msf exploit(ms08_067_netapi) > set rhost 10.0.1.3
rhost => 10.0.1.3
```

**How Metasploit developers look at datastore options:**

On the development side, things are a little crazier. Datastore options actually can be found in at least four different sources: the ModuleDataStore object, active_module, session object, or the framework object.

If you're just doing module development, the best source you can trust is the ModuleDataStore object. This object has a specific load order before handing you the option you want: if the option can be found in the module's datastore, it will give you that. If not found, it will give you the one from framework. The following is an example of how to read a datastore option in a module:

```ruby
current_host = datastore['RHOST']
```

If your dev work is outside the module realm, there is a good possibility that you don't even have the ModuleDataStore object. But in some cases, you still might be able to read from the [active_module accessor](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/ui/console/driver.rb#L607) from the driver. Or if you have access to [ModuleCommandDispatcher](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/ui/console/module_command_dispatcher.rb#L28), there is a ```mod``` method too that gives you the same thing, and sometimes mixins pass this around in a ```run_simple``` method while dispatching a module. One example you can look at is the [Msf::Ui::Console::CommandDispatcher::Auxiliary](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/ui/console/command_dispatcher/auxiliary.rb) class.

In some cases such as running a script in post exploitation, you might not have ModuleDataStore or even active_module, but you probably still have a session object. There should be an ```exploit_datastore``` that gives you all the datastore options:

```ruby
session.exploit_datastore
```

### Basic vs advanced options

### Types of options

### The register_options method

### The deregister_options method

### Modifying datastore options at run-time