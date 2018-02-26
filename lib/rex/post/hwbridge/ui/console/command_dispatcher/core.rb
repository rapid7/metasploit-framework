# -*- coding: binary -*-
require 'set'
require 'rex/post/hwbridge'
require 'rex/parser/arguments'

module Rex
module Post
module HWBridge
module Ui

###
#
# Core hwbridge client commands that provide only the required set of
# commands for having a functional hwbridge client<->hardware  instance.
#
###
class Console::CommandDispatcher::Core

  include Console::CommandDispatcher

  #
  # Initializes an instance of the core command set using the supplied shell
  # for interactivity.
  #
  def initialize(shell)
    super

    self.extensions = []
    self.bgjobs     = []
    self.bgjob_id   = 0

    # keep a lookup table to refer to transports by index
    @transport_map = {}

  end

  @@irb_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                  ],
    "-e" => [ true,  "Expression to evaluate."       ])

  @@load_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help menu."                    ])

  #
  # List of supported commands.
  #
  def commands
    c = {
      "?"          => "Help menu",
      "background" => "Backgrounds the current session",
      "exit"       => "Terminate the hardware bridge session",
      "help"       => "Help menu",
      "irb"        => "Drop into irb scripting mode",
      "load"       => "Load one or more meterpreter extensions",
      "run"        => "Executes a meterpreter script or Post module",
      "bgrun"      => "Executes a meterpreter script as a background thread",
      "bgkill"     => "Kills a background meterpreter script",
      "bglist"     => "Lists running background scripts",
      "sessions"   => "Quickly switch to another session",
      "status"     => "Fetch bridge status information",
      "specialty"  => "Hardware devices specialty",
      "reset"      => "Resets the device (NOTE: on some devices this is a FULL FACTORY RESET)",
      "reboot"     => "Reboots the device (usually only supported by stand-alone devices)",
      "load_custom_methods" => "Loads custom HW commands if any"
    }

    if msf_loaded?
      c["info"] = "Displays information about a Post module"
    end

    c
  end

  def name
    "Core"
  end

  def cmd_sessions_help
    print_line('Usage: sessions <id>')
    print_line
    print_line('Interact with a different session Id.')
    print_line('This works the same as calling this from the MSF shell: sessions -i <session id>')
    print_line
  end

  def cmd_sessions(*args)
    if args.length.zero? || args[0].to_i.zero?
      cmd_sessions_help
    elsif args[0].to_s == client.name.to_s
      print_status("Session #{client.name} is already interactive.")
    else
      print_status("Backgrounding session #{client.name}...")
      # store the next session id so that it can be referenced as soon
      # as this session is no longer interacting
      client.next_session = args[0]
      client.interacting = false
    end
  end

  def cmd_background_help
    print_line "Usage: background"
    print_line
    print_line "Stop interacting with this session and return to the parent prompt"
    print_line
  end

  def cmd_background
    print_status "Backgrounding session #{client.name}..."
    client.interacting = false
  end

  #
  # Terminates the hwbridge
  #
  def cmd_exit(*args)
    print_status("Shutting down the hardware bridge...")
    shell.stop
  end

  alias cmd_quit cmd_exit

  def cmd_irb_help
    print_line "Usage: irb"
    print_line
    print_line "Execute commands in a Ruby environment"
    print @@irb_opts.usage
  end

  #
  # Runs the IRB scripting shell
  #
  def cmd_irb(*args)
    expressions = []

    # Parse the command options
    @@irb_opts.parse(args) do |opt, idx, val|
      case opt
      when '-e'
        expressions << val
      when '-h'
        return cmd_irb_help
      end
    end

    session = client
    framework = client.framework

    if expressions.empty?
      print_status("Starting IRB shell")
      print_status("The 'client' variable holds the hwbridge client\n")

      Rex::Ui::Text::IrbShell.new(binding).run
    else
      expressions.each { |expression| eval(expression, binding) }
    end
  end

  def cmd_info_help
    print_line 'Usage: info <module>'
    print_line
    print_line 'Prints information about a post-exploitation module'
    print_line
  end

  #
  # Show info for a given Post module.
  #
  # See also +cmd_info+ in lib/msf/ui/console/command_dispatcher/core.rb
  #
  def cmd_info(*args)
    return unless msf_loaded?

    if args.length != 1 || args.include?('-h')
      cmd_info_help
      return
    end

    module_name = args.shift
    mod = client.framework.modules.create(module_name);

    if mod.nil?
      print_error 'Invalid module: ' << module_name
    end

    if mod
      print_line(::Msf::Serializer::ReadableText.dump_module(mod))
      mod_opt = ::Msf::Serializer::ReadableText.dump_options(mod, '   ')
      print_line("\nModule options (#{mod.fullname}):\n\n#{mod_opt}") if mod_opt && mod_opt.length > 0
    end
  end

  def cmd_info_tabs(*args)
    return unless msf_loaded?
    tab_complete_postmods
  end

  def cmd_status_help
    print_line("Usage: status")
    print_line
    print_line "Retrives the devices current status and statistics"
  end

  #
  # Get the HW bridge devices status
  #
  def cmd_status(*args)
    if args.length > 0
      cmd_status_help
      return true
    end
    status = client.get_status
    stats = client.get_statistics
    if status.has_key? 'operational'
      op = 'Unknown'
      op = 'Yes' if status['operational'] == 1
      op = 'No' if status['operational'] == 2
      print_status("Operational: #{op}")
    end
    print_status("Device: #{status['device_name']}") if status.key? 'device_name'
    print_status("FW Version: #{status['fw_version']}") if status.key? 'fw_version'
    print_status("HW Version: #{status['hw_version']}") if status.key? 'hw_version'
    print_status("Uptime: #{stats['uptime']} seconds") if stats.key? 'uptime'
    print_status("Packets Sent: #{stats['packet_stats']}") if stats.key? 'packet_stats'
    print_status("Last packet Sent: #{Time.at(stats['last_request'])}") if stats.key? 'last_request'
    print_status("Voltage: #{stats['voltage']}") if stats.key? 'voltage' and not stats['voltage'] == 'not supported'
  end

  def cmd_specialty_help
    print_line("Usage: specialty")
    print_line
    print_line "Simple helper function to see what the devices specialty is"
  end

  #
  # Get the Hardware specialty
  #
  def cmd_specialty(*args)
    if args.length > 0
      cmd_specialty_help
      return true
    end
    print_line client.exploit.hw_specialty.to_s
  end

  def cmd_reset_help
    print_line("Resets the device.  In some cases this can be used to perform a factory reset")
    print_line
  end

  #
  # Performs a device reset or factory reset
  #
  def cmd_reset(*args)
    if args.length > 0
      cmd_reset_help
      return
    end
    client.reset
  end

  def cmd_reboot_help
    print_line("Reboots the device.  This command typically only works on independent devices that")
    print_line("are not attached to a laptop or other system")
    print_line
  end

  #
  # Perform a device reboot
  #
  def cmd_reboot(*args)
    if args.length > 0
      cmd_reboot_help
      return
    end
    client.reboot
  end

  def cmd_load_custom_methods_help
    print_line("Usage: load_custom_methods")
    print_line
    print_line "Checks to see if there are any custom HW commands and loads as"
    print_line "interactive commands in your session."
  end

  #
  # Loads custom methods if any exist
  #
  def cmd_load_custom_methods(*args)
    if args.length > 0
      cmd_load_custom_methods_help
      return true
    end
    res = client.get_custom_methods
    if res.has_key? 'Methods'
      cmd_load("custom_methods")
      self.shell.dispatcher_stack.each do |dispatcher|
        if dispatcher.name =~ /custom methods/i
          dispatcher.load_methods(res['Methods'])
        end
      end
      print_status("Loaded #{res['Methods'].size} method(s)")
    else
      print_status("Not supported")
    end
  end

  def cmd_load_help
    print_line("Usage: load ext1 ext2 ext3 ...")
    print_line
    print_line "Loads a hardware extension module or modules."
    print_line @@load_opts.usage
  end

  #
  # Loads one or more meterpreter extensions.
  #
  def cmd_load(*args)
    if args.length.zero?
      args.unshift("-h")
    end

    @@load_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        cmd_load_help
        return true
      end
    }

    # Load each of the modules
    args.each { |m|
      md = m.downcase

      if extensions.include?(md)
        print_error("The '#{md}' extension has already been loaded.")
        next
      end

      print("Loading extension #{md}...")

      begin
        # Use the remote side, then load the client-side
        #if (client.core.use(md) == true)
          client.add_extension(md) # NOTE: Doesn't work, going to use core instead
          add_extension_client(md)
        #end
      rescue
        print_line
        log_error("Failed to load extension: #{$!}")
        next
      end

      print_line("success.")
    }

    return true
  end

  def cmd_run_help
    print_line "Usage: run <script> [arguments]"
    print_line
    print_line "Executes a ruby script or Metasploit Post module in the context of the"
    print_line "hardware bridge session.  Post modules can take arguments in var=val format."
    print_line "Example: run post/foo/bar BAZ=abcd"
    print_line
  end

  #
  # Executes a script in the context of the hwbridge session.
  #
  def cmd_run(*args)
    if args.length.zero?
      cmd_run_help
      return true
    end

    # Get the script name
    begin
      script_name = args.shift
      # First try it as a Post module if we have access to the Metasploit
      # Framework instance.  If we don't, or if no such module exists,
      # fall back to using the scripting interface.
      if msf_loaded? && mod = client.framework.modules.create(script_name)
        original_mod = mod
        reloaded_mod = client.framework.modules.reload_module(original_mod)

        unless reloaded_mod
          error = client.framework.modules.module_load_error_by_path[original_mod.file_path]
          print_error("Failed to reload module: #{error}")

          return
        end

        opts = (args + [ "SESSION=#{client.sid}" ]).join(',')
        reloaded_mod.run_simple(
          #'RunAsJob' => true,
          'LocalInput'  => shell.input,
          'LocalOutput' => shell.output,
          'OptionStr'   => opts
        )
      else
        # the rest of the arguments get passed in through the binding
        client.execute_script(script_name, args)
      end
    rescue
      print_error("Error in script: #{$!.class} #{$!}")
      elog("Error in script: #{$!.class} #{$!}")
      dlog("Callstack: #{$@.join("\n")}")
    end
  end

  def cmd_run_tabs(str, words)
    tabs = []
    if !words[1] || !words[1].match(/^\//)
      begin
        if msf_loaded?
          tabs = tab_complete_postmods
        end
        [  # We can just use Meterpreters script path
          ::Msf::Sessions::HWBridge.script_base,
          ::Msf::Sessions::HWBridge.user_script_base
        ].each do |dir|
          next unless ::File.exist? dir
          tabs += ::Dir.new(dir).find_all { |e|
            path = dir + ::File::SEPARATOR + e
            ::File.file?(path) && ::File.readable?(path)
          }
        end
      rescue Exception
      end
    end
    return tabs.map { |e| e.sub(/\.rb$/, '') }
  end

  #
  # Executes a script in the context of the hardware bridge session in the background
  #
  def cmd_bgrun(*args)
    if args.length.zero?
      print_line(
        "Usage: bgrun <script> [arguments]\n\n" +
        "Executes a ruby script in the context of the hardware bridge session.")
      return true
    end

    jid = self.bgjob_id
    self.bgjob_id += 1

    # Get the script name
    self.bgjobs[jid] = Rex::ThreadFactory.spawn("HWBridgeBGRun(#{args[0]})-#{jid}", false, jid, args) do |myjid,xargs|
      ::Thread.current[:args] = xargs.dup
      begin
        # the rest of the arguments get passed in through the binding
        client.execute_script(args.shift, args)
      rescue ::Exception
        print_error("Error in script: #{$!.class} #{$!}")
        elog("Error in script: #{$!.class} #{$!}")
        dlog("Callstack: #{$@.join("\n")}")
      end
      self.bgjobs[myjid] = nil
      print_status("Background script with Job ID #{myjid} has completed (#{::Thread.current[:args].inspect})")
    end

    print_status("Executed HWBridge with Job ID #{jid}")
  end

  #
  # Map this to the normal run command tab completion
  #
  def cmd_bgrun_tabs(*args)
    cmd_run_tabs(*args)
  end

  #
  # Kill a background job
  #
  def cmd_bgkill(*args)
    if args.length.zero?
      print_line("Usage: bgkill [id]")
      return
    end

    args.each do |jid|
      jid = jid.to_i
      if self.bgjobs[jid]
        print_status("Killing background job #{jid}...")
        self.bgjobs[jid].kill
        self.bgjobs[jid] = nil
      else
        print_error("Job #{jid} was not running")
      end
    end
  end

  #
  # List background jobs
  #
  def cmd_bglist(*args)
    self.bgjobs.each_index do |jid|
      if self.bgjobs[jid]
        print_status("Job #{jid}: #{self.bgjobs[jid][:args].inspect}")
      end
    end
  end

  def cmd_info_help
    print_line 'Usage: info <module>'
    print_line
    print_line 'Prints information about a post-exploitation module'
    print_line
  end


  @@client_extension_search_paths = [ ::File.join(Rex::Root, "post", "hwbridge", "ui", "console", "command_dispatcher") ]

  def self.add_client_extension_search_path(path)
    @@client_extension_search_paths << path unless @@client_extension_search_paths.include?(path)
  end
  def self.client_extension_search_paths
    @@client_extension_search_paths
  end

protected

  attr_accessor :extensions # :nodoc:
  attr_accessor :bgjobs, :bgjob_id # :nodoc:

  CommDispatcher = Console::CommandDispatcher

  #
  # Loads the client extension specified in mod
  #
  def add_extension_client(mod)
    loaded = false
    klass = nil
    self.class.client_extension_search_paths.each do |path|
      path = ::File.join(path, "#{mod}.rb")
      klass = CommDispatcher.check_hash(path)
      if klass.nil?
        old = CommDispatcher.constants
        next unless ::File.exist? path

        if require(path)
          new = CommDispatcher.constants
          diff = new - old

          next if diff.empty?

          klass = CommDispatcher.const_get(diff[0])

          CommDispatcher.set_hash(path, klass)
          loaded = true
          break
        else
          print_error("Failed to load client script file: #{path}")
          return false
        end
      else
        # the klass is already loaded, from a previous invocation
        loaded = true
        break
      end
    end
    unless loaded
      print_error("Failed to load client portion of #{mod}.")
      return false
    end

    # Enstack the dispatcher
    self.shell.enstack_dispatcher(klass)

    # Insert the module into the list of extensions
    self.extensions << mod
  end

  def tab_complete_postmods
    tabs = client.framework.modules.post.map { |name, klass|
      mod = client.framework.modules.post.create(name)
      if mod && mod.session_compatible?(client)
        mod.fullname.dup
      else
        nil
      end
    }

    # nils confuse readline
    tabs.compact
  end

end

end
end
end
end
