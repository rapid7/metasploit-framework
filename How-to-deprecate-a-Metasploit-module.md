Metasploit has a very specific way to deprecate a module. To do so, you must be using the [Msf::Module::Deprecated](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/module/deprecated.rb) mixin. The reason you must be using this mixin is because two things:

1. You are required to set a deprecation date. That way we know when to remove it.
2. You are required to set a replacement of the module you wish to deprecate.

## Usage

To use the ```Msf::Module::Deprecated```, here's how:

1 - In the module you wish to deprecate, add the following ```require``` statement:

```ruby
require 'msf/core/module/deprecated'
```

2 - Under ```class metasploit3``` of your module, include the following:

```
include Msf::Module::Deprecated
```

3 - Define the ```DEPRECATION_DATE``` constant:

```ruby
DEPRECATION_DATE = Date.new(2014, 9, 21) # Sep 21
```

4 - Define the ```DEPRECATION_REPLACEMENT``` constant:

```ruby
# The new module is exploits/linux/http/dlink_upnp_exec_noauth
DEPRECATION_REPLACEMENT = 'exploits/linux/http/dlink_upnp_exec_noauth'
```