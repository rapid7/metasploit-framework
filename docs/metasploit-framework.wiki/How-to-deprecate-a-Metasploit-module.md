Metasploit has a very specific way to deprecate a module. To do so, you must be using the [Msf::Module::Deprecated](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/module/deprecated.rb) mixin. The reason you must be using this mixin is because two things:

1. You are required to set a deprecation date. That way we know when to remove it, which is done manually.
2. You are optionally allowed to set a replacement of the module you wish to deprecate.

## Usage

To use the ```Msf::Module::Deprecated```, here's how:

1 - Under ```class MetasploitModule``` of your module, include the following:

```ruby
include Msf::Module::Deprecated
```

2a - When moving a module, use the ```moved_from``` method in the new module to add an alias to the old module name:

```ruby
moved_from 'auxiliary/analyze/jtr_windows_fast'
```

2b - Use the ```deprecated``` method to assign a deprecation date and replacement module:

```ruby
deprecated(Date.new(2014, 9, 21), 'exploit/linux/http/dlink_upnp_exec_noauth')
```

2c - Alternatively, define the ```DEPRECATION_DATE``` and ```DEPRECATION_REPLACEMENT``` constants:

```ruby
DEPRECATION_DATE = Date.new(2014, 9, 21) # Sep 21
# The new module is exploit/linux/http/dlink_upnp_exec_noauth
DEPRECATION_REPLACEMENT = 'exploit/linux/http/dlink_upnp_exec_noauth'
```

When the user loads that module, they should see a warning like this:

```msf
msf > use exploit/windows/misc/test 

[!] ************************************************************************
[!] *             The module windows/misc/test is deprecated!              *
[!] *              It will be removed on or about 2014-09-21               *
[!] *        Use exploit/linux/http/dlink_upnp_exec_noauth instead        *
[!] ************************************************************************
```

## Code example

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Module::Deprecated

  deprecated(Date.new(2014, 9, 21), 'exploit/linux/http/dlink_upnp_exec_noauth')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Msf::Module::Deprecated Example',
        'Description' => %q{
          This shows how to use Msf::Module::Deprecated.
        },
        'Author' => [ 'sinn3r' ],
        'License' => MSF_LICENSE,
        'References' => [ [ 'URL', 'http://metasploit.com' ] ],
        'DisclosureDate' => '2014-04-01',
        'Targets' => [ [ 'Automatic', {} ] ],
        'DefaultTarget' => 0
      )
    )
  end

  def exploit
    print_debug('Code example')
  end

end
```
