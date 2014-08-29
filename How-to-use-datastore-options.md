A datastore option is a type of variable that can be set by the user that allows various components of Metasploit to be more configurable. For example, in msfconsole, you can set the ConsoleLogging option in order to log all the console input/output - something that's kind of handy for documentation purposes during a pentest. When you load a module, you get to have a lot more options, but they're mostly module-specific. The best way to find out what options you can set is by using these commands:

```show options``` - Shows you all the basic options.
```show advanced``` - Shows you all the advanced options.
```set``` - Shows you everything. Obviously you also use this command to set an option.

### Module level options vs global options

### Basic vs advanced options

### Types of options

### The register_options method

### The deregister_options method

### Modifying datastore options at run-time