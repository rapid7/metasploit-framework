## Acceptance Tests

A slower test suite that ensures high level functionality works as expected,
such as verifying msfconsole opens successfully, and can generate Meterpreter payloads,
create handlers, etc.

### Examples

Running Meterpreter test suite:

```
bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

Skip loading of Rails/Metasploit with:
```
SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance
```

Run only the PHP Meterpreter test suite on Unix / Windows:
```
METERPRETER=php bundle exec rspec './spec/acceptance/meterpreter_spec.rb'

$env:METERPRETER = 'php'; bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

### Debugging

If a test has failed you can enter into an interactive breakpoint with:
```
require 'pry'; binding.pry
```

To interact with a console instance, forwarding the current stdin to the console's stdin,
and writing the console's output to stdout:

```
console.interact
```

Once inside the console, the following 'commands' can be used within the context of
the interactive msfconsole:

- `!continue` - Continue, similar to Pry's continue functionality
- `!exit` - Exit the Ruby process entirely, similar to Pry's exit functionality
