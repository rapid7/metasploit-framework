# Datastore Option Overview

A datastore option is a type of variable that can be set by the user, allowing various components of Metasploit to be
more configurable during use. For example, in msfconsole, you can set the ConsoleLogging option in order to log all the
console input/output - something that's kind of handy for documentation purposes during a pentest. When you load a
module, there will be a lot more options registered by the mixin(s) or the module. Some common ones include RHOSTS and
RPORT for a server-side exploit or auxiliary module, SRVHOST for a client-side module, etc. The best way to find out
exactly what datastore options you can set is by using these commands:

* `show options` - Shows you all the basic options.
* `show advanced` - Shows you all the advanced options.
* `show missing` - Shows you all the required options you have not configured.
* `set` - Shows you everything. Obviously, you also use this command to set an option.

Option sources: ModuleDataStore, active_module, session, and framework

## How users look at datastore options

On the user's side, datastore options are seen as global or module-level: Global means all the modules can use that
option, which can be set by using the `setg` command. Module-level means only that particular module you're using
remembers that datastore option, no other components will know about it. You are setting a module-level option if you
load a module first, and then use the `set` command, like the following:

```msf
msf > use exploit/windows/smb/ms08_067_netapi
msf exploit(ms08_067_netapi) > set rhost 10.0.1.3
rhost => 10.0.1.3
```

## How Metasploit developers look at datastore options

On the development side, things are a little crazier. Datastore options actually can be found in at least four different
sources: the ModuleDataStore object, active_module, session object, or the framework object.

If you're just doing module development, the best source you can trust is the ModuleDataStore object. This object has a
specific load order before handing you the option you want: if the option can be found in the module's datastore, it
will give you that. If not found, it will give you the one from framework. The following is an example of how to read a
datastore option in a module:

```ruby
current_host = datastore['RHOST']
```

If your dev work is outside the module realm, there is a good possibility that you don't even have the ModuleDataStore object. But in some cases, you still might be able to read from the [active_module accessor](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/ui/console/driver.rb#L607) from the driver. Or if you have access to [ModuleCommandDispatcher](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/ui/console/module_command_dispatcher.rb#L28), there is a `mod` method too that gives you the same thing, and sometimes mixins pass this around in a `run_simple` method while dispatching a module. One example you can look at is the [Msf::Ui::Console::CommandDispatcher::Auxiliary](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/ui/console/command_dispatcher/auxiliary.rb) class.

In some cases such as running a script in post exploitation, you might not have ModuleDataStore or even active_module, but you should still have a session object. There should be an `exploit_datastore` that gives you all the datastore options:

```ruby
session.exploit_datastore
```

If you don't have access to the module, or to a session object, the last source is obviously the framework object, and there is ALWAYS a framework object. However, like we said earlier, if the user sets a module-level option, no other components will see it, this includes the framework object:

```ruby
framework.datastore
```

So now you know there are multiple sources of datastore options. And hopefully at this point you are well aware that not all sources necessarily share the same thing. If you have to try everything, as a general rule, this should be your load order:

1. Try from the ModuleDataStore
2. Try from active_module
3. Try from session
4. Try from framework

# Core option types

All core datastore option types are defined in the [option_container.rb](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/option_container.rb) file as classes. You should always pick the most appropriate one because each has its own input validator.

When you initialize an option during datastore registration, it should be in the following format:

```ruby
OptSomething.new(option_name, [boolean, description, value, *enums*], aliases: *aliases*, conditions: *conditions*)
```

* **option_name** - Clearly means the name of the datastore option.
* **boolean** - The first attribute, true means this is a required option, false means optional.
* **description** - A short description about this option
* **value** - A default value. Note if the first attribute is false, you don't need to provide a value, it'll be set to
  nil automatically.
* **enums** - *optional* An array of acceptable values, e.g. `%w[ LEFT RIGHT ]`.
* **aliases** - *optional*, *key-word only* An array of additional names that refer to this option. This is useful when
  renaming a datastore option to retain backward compatibility. See the [Renaming datastore
  options](#Renaming-datastore-options) section for more information
* **conditions** - *optional*, *key-word only* An array of a condition for which the option should be displayed. This
  can be used to hide options when they are irrelevant based on other configurations. See the [Filtering datastore
  options](#Filtering-datastore-options) section for more information.
* **fallbacks** *optional*, *key-word only* An array of names that will be used as a fallback if the main option name is
  defined by the user. This is useful in the scenario of wanting specialised option names such as `SMBUser`, but to also
  support gracefully checking a list of more generic fallbacks option names such as `Username`. This functionality is 
  currently behind a feature flag, set with `features set datastore_fallbacks true` in msfconsole

Now let's talk about what classes are available:

## OptAddress
An input that is an IPv4 address. Code example:

```ruby
OptAddress.new('IP', [ true, 'Set an IP', '10.0.1.3' ])
```

## OptAddressRange
An input that is a range of IPv4 addresses, for example: 10.0.1.1-10.0.1.20, or 10.0.1.1/24. You can also supply a file path instead of a range, and it will automatically treat that file as a list of IPs. Or, if you do the rand:3 syntax, with 3 meaning 3 times, it will generate 3 random IPs for you. Basic code example:

```ruby
OptAddressRange.new('Range', [ true, 'Set an IP range', '10.0.1.3-10.0.1.23' ])
```

## OptBool
Boolean option. It will validate if the input is a variant of either true or false. For example: y, yes, n, no, 0, 1, etc. Code example:

```ruby
OptBool.new('BLAH', [ true, 'Set a BLAH option', false ])
```

## OptEnum
Basically this will limit the input to specific choices. For example, if you want the input to be either "apple", or "orange", and nothing else, then OptEnum is the one for you. Code example:

```ruby
# Choices are: apple or range, defaults to apple
OptEnum.new('FRUIT', [ true, 'Set a fruit', 'apple', ['apple', 'orange']])
```

## OptInt
This can be either a hex value, or decimal.

```ruby
OptInt.new('FILE', [ true, 'A hex or decimal', 1024 ])
```

## OptPath
If your datastore option is asking for a local file path, then use this.

```ruby
OptPath.new('FILE', [ true, 'Load a local file' ])
```

## OptPort
For an input that's meant to be used as a port number. This number should be between 0 - 65535. Code example:

```ruby
OptPort.new('RPORT', [ true, 'Set a port', 21 ])
```

## OptRaw
It actually functions exactly the same as OptString.

## OptRegexp
Datastore option is a regular expression.

```ruby
OptRegexp.new('PATTERN', [true, 'Match a name', '^alien']),
```

**Other types:**

In some cases, there might not be a well-suited datastore option type for you. The best example is an URL: even though there's no such thing as a OptUrl, what you can do is use the OptString type, and then in your module, do some validation for it, like this:

```ruby
def valid?(input)
  if input =~ /^http:\/\/.+/i
    return true
  else
    # Here you can consider raising OptionValidateError
    return false
  end
end

if valid?(datastore['URL'])
  # We can do something with the URL
else
  # Not the format we're looking for. Refuse to do anything.
end
```

## OptString
Typically for a string option. If the input begins with "file://", OptString will also automatically assume this is a file, and read from it. However, there is no file path validation when this happens, so if you want to load a file, you should use the OptPath instead, and then read the file yourself. Code example:

```ruby
OptString.new('MYTEST', [ true, 'Set a MYTEST option', 'This is a default value' ])
```

# Registering and deregistering module options

## The register_options method

The `register_options` method can register multiple basic datastore options. Basic datastore options are the ones that either must be configured, such as the RHOST option in a server-side exploit. Or it's very commonly used, such as various username/password options found in a login module.

The following is an example of registering multiple datastore options in a module:

```ruby
register_options(
  [
    OptString.new('SUBJECT', [ true, 'Set a subject' ]),
    OptString.new('MESSAGE', [ true, 'Set a message' ])
  ])
```

## The register_advanced_options method

The `register_advanced_options` method can register multiple advanced datastore options. Advanced datastore options are the ones that never require the user to configure before using the module. For example, the Proxies option is almost always considered as "advanced". But of course, it can also mean that's something that most user will find difficult to configure.

An example of register an advanced option:

```ruby
register_advanced_options(
  [
    OptInt.new('Timeout', [ true, 'Set a timeout, in seconds', 60 ])
  ])
```

## The deregister_options method

The `deregister_options` method can deregister either basic or advanced options. Usage is really straight-forward:

```ruby
deregister_options('OPTION1', 'OPTION2', 'OPTION3')
```

# Changing the default value for a datastore option

When a datastore option is already registered by a mixin, there are still ways to change the default value from the
module. You can either use the `register_options` method, or adding a DefaultOptions key in the module's metadata. Using
the DefaultOptions key is preferred because the option's description and other attributes will remain unchanged.

## Using register_options to change the default value

One of the advantages of using `register_options` is that if the datastore option is advanced, this allows it to be on
the basic option menu, meaning when people do "show options" on msfconsole, that option will be there instead. You also
get to change the option description, and whether it should be required or not with this method.

## Using DefaultOptions to change the default value

When Metasploit initializes a module, an `import_defaults` method is [called](https://github.com/rapid7/metasploit-
framework/blob/master/lib/msf/core/module.rb#L581). This method will update all existing datastore options (which is why
`register_options` can be used to update default values), and then it will specifically check the DefaultOptions key
from the module's metadata, and update again.

Here's an example of an exploit module's initialize portion with the DefaultOptions key:

```ruby
def initialize(info = {})
  super(
    update_info(
      info,
      'Name' => 'Module name',
      'Description' => %q{
        This is an example of setting the default value of RPORT using the DefaultOptions key
      },
      'License' => MSF_LICENSE,
      'Author' => [ 'Name' ],
      'References' => [
        [ 'URL', '' ]
      ],
      'Platform' => 'win',
      'Targets' => [
        [ 'Windows', { 'Ret' => 0x41414141 } ]
      ],
      'Payload' => {
        'BadChars' => "\x00"
      },
      'DefaultOptions' => {
        'RPORT' => 8080
      },
      'Privileged' => false,
      'DisclosureDate' => '',
      'DefaultTarget' => 0
    )
  )
end
```

# Modifying datastore options at run-time

Currently, the safest way to modify a datastore option at run-time is to override a method. For example, some mixins retrieve the RPORT option like this:

```ruby
def rport
  datastore['RPORT']
end
```

In that scenario, you can override this rport method from your module, and return a different value:

```ruby
def rport
  80
end
```

This way, when a mixin wants that information, it will end up with the value 80, and not whatever is actually in `datastore['RPORT']`.

# Ideal datastore naming

Normal options are always UPPERCASE, advanced options are CamelCase, advanced options with a similar purpose are
Prefixed::CamelCase.

## Renaming datastore options

Options can be renamed and retain backward compatibility by using the `alias:` keyword argument in the new option. For
example, to rename `OldOption` to `NewOption`, the new definitions would look something like:

```ruby
OptString.new('NewOption', [true, 'A (sort of) new option', 'hello'], aliases: %w[ OldOption ])
```

# Filtering datastore options

Options can be hidden in certain conditions using the `conditions:` keyword argument to their definition. This allows
options to be hidden when they are not relevant based on the value of another option, the selected target or the
selected action.

The syntax for a condition is `*thing* *operator* *value*`.

* **thing** - One of `ACTION`, `TARGET` or the name of a datastore option.
* **operator** - One of `==`, `!=`, `in`, `nin`. In the case of `in` and `nin` (not-in), the *value* is an array of values.
* **value** - The value to check for in the condition.

When the condition evaluates to true, the option is considered active and displayed to the user. Datastore options with
no defined conditions are active by default.

## Filter examples

1. `conditions: %w[VERSION == 5]` - Active when the `VERSION` datastore option is 5.
1. `conditions: ['ACTION', 'in', %w[SSRF EXEC SECSTORE]]` - Active when the `ACTION` is one of `SSRF`, `EXEC` or
  `SECSTORE`
