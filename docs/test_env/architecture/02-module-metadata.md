# Module Metadata Integration

## What I Verified

I wrote and ran `test_final.rb` to verify how to access module metadata. Here is the test script I used:

```ruby
#!/usr/bin/env ruby

$LOAD_PATH.unshift(File.expand_path('lib', __dir__))
require 'msfenv'
require 'msf/core'

framework = Msf::Simple::Framework.create
mod = framework.modules.create('exploit/multi/http/jenkins_script_console')

puts "Module: #{mod.fullname}"
puts ""

# Test: Can we read module_info via send?
puts "=== Reading module_info via send ==="
info = mod.send(:module_info)
puts "Type: #{info.class}"
puts "Keys count: #{info.keys.length}"
puts "Has Name? #{info.key?('Name')}"
puts "Name: #{info['Name']}"
puts ""

# Test: Can we add a custom key?
puts "=== Adding custom key ==="
info['VulnEnv'] = {
  'definition' => 'jenkins',
  'default_version' => '2.361',
  'port_mapping' => { 8080 => 'RPORT' }
}

puts "Added VulnEnv"
puts "Has VulnEnv? #{info.key?('VulnEnv')}"
puts "VulnEnv: #{info['VulnEnv'].inspect}"
puts ""

# Test: Can we read it back?
puts "=== Reading back ==="
info2 = mod.send(:module_info)
puts "Same object? #{info.equal?(info2)}"
puts "Has VulnEnv? #{info2.key?('VulnEnv')}"
puts "VulnEnv: #{info2['VulnEnv'].inspect}"
```

### Output I Got

```
Module: exploit/multi/http/jenkins_script_console

=== Reading module_info via send ===
Type: Hash
Keys count: 18
Has Name? true
Name: Jenkins-CI Script-Console Java Execution

=== Adding custom key ===
Added VulnEnv
Has VulnEnv? true
VulnEnv: {"definition"=>"jenkins", "default_version"=>"2.361", "port_mapping"=>{8080=>"RPORT"}}

=== Reading back ===
Same object? true
Has VulnEnv? true
VulnEnv: {"definition"=>"jenkins", "default_version"=>"2.361", "port_mapping"=>{8080=>"RPORT"}}
```

### What This Proves

| Test | Result |
|------|--------|
| `mod.send(:module_info)` returns a Hash | ✅ Yes |
| The Hash contains standard keys like `Name` | ✅ Yes |
| I can write a custom key `VulnEnv` to it | ✅ Yes |
| The custom key persists when read back | ✅ Yes |
| It's the same object (not a copy) | ✅ Yes |

## Source Code Evidence

From `lib/msf/core/module/module_info.rb` line 69:

```ruby
protected

# @!attribute module_info
attr_accessor :module_info
```

`module_info` is a **protected** `attr_accessor`. That is why:
- `mod.module_info` raises `NoMethodError` (protected method)
- `mod.send(:module_info)` works (bypasses access control)

The framework itself uses `module_info` internally in `lib/msf/core/module.rb`:

```ruby
# Line 116
self.module_info = info

# Line 129-132
self.author = Msf::Author.transform(merge_module_info_with_target_info(module_info, 'Author'))
self.arch = Rex::Transformer.transform(merge_module_info_with_target_info(module_info, 'Arch'), Array, [ String ], 'Arch')
```

And in `lib/msf/core/module/module_info.rb`:

```ruby
# Line 41
def name
  module_info['Name']
end
```

## The Correct Way to Access Module Metadata

```ruby
# In plugin's command dispatcher:
def cmd_test_env_build(args)
  # 1. Get active module from driver
  mod = driver.active_module
  raise "No active module. Use 'use <module>' first." unless mod
  
  # 2. Access module_info via send (protected accessor)
  info = mod.send(:module_info)
  
  # 3. Read VulnEnv configuration
  vuln_env = info['VulnEnv']
  raise "Module has no VulnEnv config" unless vuln_env
  
  # 4. Extract values
  definition_name = vuln_env['definition']      # 'jenkins'
  version = vuln_env['default_version']         # '2.361'
  port_mapping = vuln_env['port_mapping']       # {8080 => 'RPORT'}
  
  # 5. Load YAML definition file
  yaml_path = File.join(Msf::Config.data_directory, 'vuln_envs', "#{definition_name}.yml")
end
```

## Why send(:module_info) Is Acceptable

- `module_info` is **protected**, not private — meant for subclass/extension access
- Metasploit plugins are **framework extensions**, not external code
- The framework itself accesses `module_info` directly in the `ModuleInfo` mixin
- This is a **standard Ruby pattern** for working with protected framework internals

## Alternative: Encapsulate in Helper Method (Is it better to do or not?)

If It's not preferable not to use `send` directly everywhere:

```ruby
class Plugin::VulnEnv < Msf::Plugin
  class ConsoleCommandDispatcher
    # Encapsulate the send call for clarity
    def get_module_vuln_env(mod)
      mod.send(:module_info)['VulnEnv']
    end
    
    def cmd_test_env_build(args)
      mod = driver.active_module
      vuln_env = get_module_vuln_env(mod)
      # ...
    end
  end
end
```

## VulnEnv Schema

```ruby
'VulnEnv' => {
  'definition'      => String,   # e.g., 'jenkins' → data/vuln_envs/jenkins.yml
  'default_version' => String,   # e.g., '2.361'
  'port_mapping'    => Hash,      # { container_port => 'RPORT' }
  'datastore_overrides' => Hash   # optional: { 'TARGETURI' => '/script' }
}
```

## Resolution Flow

```
test_env build called
    ↓
driver.active_module → Msf::Module instance
    ↓
mod.send(:module_info)['VulnEnv'] → Hash or nil
    ↓
if nil: print_error("Module has no VulnEnv configuration")
    ↓
if present:
    definition = vuln_env['definition']      # 'jenkins'
    yaml_path = File.join(Msf::Config.data_directory, 'vuln_envs', "#{definition}.yml")
    definition_data = YAML.load_file(yaml_path)
    version = vuln_env['default_version']      # '2.361'
    env_config = definition_data['versions'][version]
    shared_config = definition_data['shared']
```

## Error Cases

| Condition | Error Message |
|-----------|--------------|
| No active module | "No active module. Use 'use <module>' first." |
| Module has no VulnEnv | "Module does not define a vulnerable environment configuration." |
| Definition file not found | "Environment definition not found: data/vuln_envs/{name}.yml" |
| Version not found in definition | "Version '{version}' not defined for '{name}'" |
