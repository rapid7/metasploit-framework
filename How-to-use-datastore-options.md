A datastore option is a type of variable that can be set by the user, allowing various components of Metasploit to be more configurable during use. For example, in msfconsole, you can set the ConsoleLogging option in order to log all the console input/output - something that's kind of handy for documentation purposes during a pentest. When you load a module, there will be a lot more options registered by the mixin(s) or the module. Some common ones include: RHOST and RPORT for a server-side exploit or auxiliary module, SRVHOST for a client-side module, etc.

The best way to find out exactly what datastore options you can set is by using these commands:

* ```show options``` - Shows you all the basic options.
* ```show advanced``` - Shows you all the advanced options.
* ```set``` - Shows you everything. Obviously you also use this command to set an option.

### Module level options vs global options

### Basic vs advanced options

### Types of options

### The register_options method

### The deregister_options method

### Modifying datastore options at run-time