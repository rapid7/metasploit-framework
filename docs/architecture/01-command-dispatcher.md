# Command Dispatcher Architecture

## What This Document Is
This defines how the `test_env` command will be added to msfconsole.

## How Commands Work in Metasploit (From Source Code I Read)

### 1. Plugin Registration
From `plugins/sample.rb`, I saw:
- Plugin inherits from `Msf::Plugin`
- Plugin has an inner `ConsoleCommandDispatcher` class
- Dispatcher `include Msf::Ui::Console::CommandDispatcher`
- `commands` method returns a hash: `{ 'command_name' => 'description' }`
- `initialize` calls `add_console_dispatcher(ConsoleCommandDispatcher)`
- `cleanup` calls `remove_console_dispatcher('Name')`

### 2. Command Routing
From `lib/rex/ui/text/dispatcher_shell.rb` line 576, I saw:
```ruby
def run_command(dispatcher, method, arguments)
```
When I type `test_env build`, this happens:
1. Shell parses the line into `["test_env", "build"]`
2. Shell finds my plugin's dispatcher in `dispatcher_stack`
3. Shell calls `run_command(my_dispatcher, "test_env", ["build"])`
4. Which calls `my_dispatcher.cmd_test_env("build")`

### 3. Multi-Command Pattern
From `lib/msf/ui/console/command_dispatcher/jobs.rb`, I saw:
- One dispatcher can handle multiple commands via `commands` hash
- `cmd_jobs(*args)` uses `args.shift` to get the subcommand
- `cmd_rename_job_tabs` provides tab completion
- `cmd_jobs_help` prints usage information

## My Design: test_env Command Dispatcher

### Class Structure
```
Msf::Plugin
└── Msf::Plugin::VulnEnv
    └── Msf::Plugin::VulnEnv::ConsoleCommandDispatcher
        └── (includes Msf::Ui::Console::CommandDispatcher)
```

### Commands Hash
| Command | Description |
|---------|-------------|
| `test_env` | Manage vulnerable test environments |

### Subcommands (Handled Inside cmd_test_env)
| Subcommand | Handler Method | What It Does |
|-----------|---------------|--------------|
| `build` | `cmd_test_env_build(args)` | Build and launch environment for active module |
| `list` | `cmd_test_env_list(args)` | Show all tracked environments |
| `stop <ID>` | `cmd_test_env_stop(args)` | Stop a running container |
| `start <ID>` | `cmd_test_env_start(args)` | Restart a stopped container |
| `remove <ID>` | `cmd_test_env_remove(args)` | Tear down a container |
| `remove-all` | `cmd_test_env_remove_all(args)` | Tear down all containers |
| `exec <ID>` | `cmd_test_env_exec(args)` | Run exploit against environment |
| `help` | `cmd_test_env_help` | Show usage |

## Sample code for solid clarification
### Argument Parsing Logic
```ruby
def cmd_test_env(*args)
  # If no args or help requested, show help
  if args.empty? || args.first == '-h' || args.first == '--help'
    cmd_test_env_help
    return
  end

  # First argument is the subcommand
  subcommand = args.shift

  # Route to appropriate handler
  case subcommand
  when 'build'      then cmd_test_env_build(args)
  when 'list'       then cmd_test_env_list(args)
  when 'stop'       then cmd_test_env_stop(args)
  when 'start'      then cmd_test_env_start(args)
  when 'remove'     then cmd_test_env_remove(args)
  when 'remove-all' then cmd_test_env_remove_all(args)
  when 'exec'       then cmd_test_env_exec(args)
  when 'help'       then cmd_test_env_help
  else
    print_error("Unknown subcommand: #{subcommand}")
    cmd_test_env_help
  end
end
```

### Tab Completion
```ruby
def cmd_test_env_tabs(str, words)
  # If only "test_env" has been typed, suggest subcommands
  if words.length == 1
    return %w[build list stop start remove remove-all exec help]
  end

  # If subcommand is stop/start/remove/exec, suggest environment IDs
  if words.length == 2
    case words[0]
    when 'stop', 'start', 'remove', 'exec'
      # TODO: Return IDs from registry (Week 6)
      return []
    end
  end

  []
end
```

### Error Handling Pattern
Every subcommand follows this pattern:
```ruby
def cmd_test_env_build(args)
  begin
    # 1. Validate preconditions
    mod = driver.active_module
    raise "No active module. Use 'use <module>' first." unless mod

    # 2. Execute logic
    # ... (implementation in later weeks)

    # 3. Report success
    print_good("Environment built successfully")

  rescue => e
    # 4. Report error
    print_error("test_env build failed: #{e.message}")
    elog("test_env build error: #{e.class} - #{e.message}")
    elog(e.backtrace.join("\n"))
  end
end
```

## Integration Points

| What I Need | Where It Comes From | How I Access It |
|-------------|-------------------|---------------|
| Framework instance | `Msf::Plugin#initialize` | `framework` (instance variable) |
| Active module | `Msf::Ui::Console::Driver#active_module` | `driver.active_module` |
| Database | `framework.db.active` | Check before DB operations |
| Console output | `Msf::Ui::Console::CommandDispatcher` | `print_status`, `print_error`, `print_good` |

## Decisions Made

| Decision | Choice | Reason |
|----------|--------|--------|
| Single command or multiple? | Single `test_env` with subcommands | Matches `jobs` pattern; cleaner namespace |
| How to parse subcommands? | `case` statement on `args.shift` | Same as `cmd_jobs` |
| Tab completion? | `cmd_test_env_tabs` method | For good UX |
| Error handling? | `begin/rescue` with `print_error` | Consistent with framework style |

