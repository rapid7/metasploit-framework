# -*- coding: binary -*-

#
# Rex
#

require 'rex/ui/text/output/buffer/stdout'

#
# Project
#

require 'msf/ui/console/command_dispatcher/encoder'
require 'msf/ui/console/command_dispatcher/exploit'
require 'msf/ui/console/command_dispatcher/nop'
require 'msf/ui/console/command_dispatcher/payload'
require 'msf/ui/console/command_dispatcher/auxiliary'
require 'msf/ui/console/command_dispatcher/post'

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Command dispatcher for core framework commands, such as module loading,
# session interaction, and other general things.
#
###
class Core
  include Metasploit::Framework::Command::Dispatcher
  include Msf::Ui::Console::CommandDispatcher

  require 'msf/ui/console/command_dispatcher/core/threads'
  include Msf::Ui::Console::CommandDispatcher::Core::Threads

  require 'msf/ui/console/command_dispatcher/core/reload_all'
  include Msf::Ui::Console::CommandDispatcher::Core::ReloadAll

  require 'msf/ui/console/command_dispatcher/core/spool'
  include Msf::Ui::Console::CommandDispatcher::Core::Spool

  #
  # Commands
  #

  command :search
  command :use

  #
  # Class Variables
  #

  # Session command options
  @@sessions_opts = Rex::Parser::Arguments.new(
    "-c" => [ true,  "Run a command on the session given with -i, or all"],
    "-h" => [ false, "Help banner"                                    ],
    "-i" => [ true,  "Interact with the supplied session ID"          ],
    "-l" => [ false, "List all active sessions"                       ],
    "-v" => [ false, "List verbose fields"                            ],
    "-q" => [ false, "Quiet mode"                                     ],
    "-d" => [ true,  "Detach an interactive session"                  ],
    "-k" => [ true,  "Terminate session"                              ],
    "-K" => [ false, "Terminate all sessions"                         ],
    "-s" => [ true,  "Run a script on the session given with -i, or all"],
    "-r" => [ false, "Reset the ring buffer for the session given with -i, or all"],
    "-u" => [ true,  "Upgrade a win32 shell to a meterpreter session" ])

  @@jobs_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ],
    "-k" => [ true,  "Terminate the specified job name."              ],
    "-K" => [ false, "Terminate all running jobs."                    ],
    "-i" => [ true,  "Lists detailed information about a running job."],
    "-l" => [ false, "List all running jobs."                         ],
    "-v" => [ false, "Print more detailed info.  Use with -i and -l"  ])

  @@connect_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ],
    "-p" => [ true,  "List of proxies to use."                        ],
    "-C" => [ false, "Try to use CRLF for EOL sequence."              ],
    "-c" => [ true,  "Specify which Comm to use."                     ],
    "-i" => [ true,  "Send the contents of a file."                   ],
    "-P" => [ true,  "Specify source port."                           ],
    "-S" => [ true,  "Specify source address."                        ],
    "-s" => [ false, "Connect with SSL."                              ],
    "-u" => [ false, "Switch to a UDP socket."                        ],
    "-w" => [ true,  "Specify connect timeout."                       ],
    "-z" => [ false, "Just try to connect, then return."              ])

  @@grep_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ],
    "-i" => [ false, "Ignore case."                                   ],
    "-m" => [ true,  "Stop after arg matches."                        ],
    "-v" => [ false, "Invert match."                                  ],
    "-A" => [ true,  "Show arg lines of output After a match."        ],
    "-B" => [ true,  "Show arg lines of output Before a match."       ],
    "-s" => [ true,  "Skip arg lines of output before attempting match."],
    "-k" => [ true,  "Keep (include) arg lines at start of output."   ],
    "-c" => [ false, "Only print a count of matching lines."          ])

  @@go_pro_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ])

  #
  # Methods
  #

  # Returns the list of commands supported by this command dispatcher
  def commands
    super.merge(
      "?"        => "Help menu",
      "back"     => "Move back from the current context",
      "banner"   => "Display an awesome metasploit banner",
      "cd"       => "Change the current working directory",
      "connect"  => "Communicate with a host",
      "color"    => "Toggle color",
      "exit"     => "Exit the console",
      "go_pro"   => "Launch Metasploit web GUI",
      "grep"     => "Grep the output of another command",
      "help"     => "Help menu",
      "info"     => "Displays information about one or more module",
      "irb"      => "Drop into irb scripting mode",
      "jobs"     => "Displays and manages jobs",
      "kill"     => "Kill a job",
      "load"     => "Load a framework plugin",
      "loadpath" => "Searches for and loads modules from a path",
      "popm"     => "Pops the latest module off the stack and makes it active",
      "pushm"    => "Pushes the active or list of modules onto the module stack",
      "previous" => "Sets the previously loaded module as the current module",
      "quit"     => "Exit the console",
      "resource" => "Run the commands stored in a file",
      "makerc"   => "Save commands entered since start to a file",
      "route"    => "Route traffic through a session",
      "save"     => "Saves the active datastores",
      "sessions" => "Dump session listings and display information about sessions",
      "set"      => "Sets a variable to a value",
      "setg"     => "Sets a global variable to a value",
      "show"     => "Displays modules of a given type, or all modules",
      "sleep"    => "Do nothing for the specified number of seconds",
      "unload"   => "Unload a framework plugin",
      "unset"    => "Unsets one or more variables",
      "unsetg"   => "Unsets one or more global variables",
      "use"      => "Selects a module by name",
      "version"  => "Show the framework and console library version numbers"
    )
  end

  #
  # Initializes the datastore cache
  #
  def initialize(driver)
    super

    @cache_payloads = nil
    @module_name_stack = []
  end

  # Cache of {Msf::DataStore data stores} for previously used modules.
  #
  # @return [Hash{String => Msf::DataStore}] Maps `Mdm::Module::Class#full_name` to {Msf::DataStore}.
  def data_store_by_module_class_full_name
    @data_store_by_module_class_full_name ||= {}
  end

  # Sets the current metasploit instance, such as been one is selected with `use`.  The old {#metasploit_instance} will
  #
  # @param metasploit_instance [Msf::Module, nil] the new metasploit instance.
  # @return [Msf::Module, nil] `metasploit_instance`
  def metasploit_instance=(metasploit_instance)
    if self.metasploit_instance
      # Save the module's datastore so that we can load it later
      # if the module is used again
      data_store_by_module_class_full_name[self.metasploit_instance.full_name] = self.metasploit_instance.datastore.dup
      @module_class_full_name_was = self.metasploit_instance.full_name
    end

    driver.metasploit_instance = metasploit_instance

    @cache_payloads = nil

    if metasploit_instance
      data_store = data_store_by_module_class_full_name[metasploit_instance.full_name]

      if data_store
        metasploit_instance.datastore.update(data_store)
      end
    end

    metasploit_instance
  end

  #
  # Returns the name of the command dispatcher.
  #
  def name
    "Core"
  end

  def cmd_color_help
    print_line "Usage: color <'true'|'false'|'auto'>"
    print_line
    print_line "Enable or disable color output."
    print_line
  end

  def cmd_color(*args)
    case args[0]
    when "auto"
      driver.output.auto_color
    when "true"
      driver.output.enable_color
    when "false"
      driver.output.disable_color
    else
      cmd_color_help
      return
    end
    driver.update_prompt
  end

  def cmd_resource_help
    print_line "Usage: resource path1 [path2 ...]"
    print_line
    print_line "Run the commands stored in the supplied files.  Resource files may also contain"
    print_line "ruby code between <ruby></ruby> tags."
    print_line
    print_line "See also: makerc"
    print_line
  end

  def cmd_resource(*args)
    if args.empty?
      cmd_resource_help
      return false
    end

    args.each do |res|
      good_res = nil
      if (File.file? res and File.readable? res)
        good_res = res
      elsif
        # let's check to see if it's in the scripts/resource dir (like when tab completed)
        [
          ::Msf::Config.script_directory + File::SEPARATOR + "resource",
          ::Msf::Config.user_script_directory + File::SEPARATOR + "resource"
        ].each do |dir|
          res_path = dir + File::SEPARATOR + res
          if (File.file?(res_path) and File.readable?(res_path))
            good_res = res_path
            break
          end
        end
      end
      if good_res
        driver.load_resource(good_res)
      else
        print_error("#{res} is not a valid resource file")
        next
      end
    end
  end

  #
  # Tab completion for the resource command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_resource_tabs(str, words)
    tabs = []
    #return tabs if words.length > 1
    if ( str and str =~ /^#{Regexp.escape(File::SEPARATOR)}/ )
      # then you are probably specifying a full path so let's just use normal file completion
      return tab_complete_filenames(str,words)
    elsif (not words[1] or not words[1].match(/^\//))
      # then let's start tab completion in the scripts/resource directories
      begin
        [
          ::Msf::Config.script_directory + File::SEPARATOR + "resource",
          ::Msf::Config.user_script_directory + File::SEPARATOR + "resource",
          "."
        ].each do |dir|
          next if not ::File.exist? dir
          tabs += ::Dir.new(dir).find_all { |e|
            path = dir + File::SEPARATOR + e
            ::File.file?(path) and File.readable?(path)
          }
        end
      rescue Exception
      end
    else
      tabs += tab_complete_filenames(str,words)
    end
    return tabs
  end

  def cmd_makerc_help
    print_line "Usage: makerc <output rc file>"
    print_line
    print_line "Save the commands executed since startup to the specified file."
    print_line
  end

  #
  # Saves commands executed since the ui started to the specified msfrc file
  #
  def cmd_makerc(*args)
    if args.empty?
      cmd_makerc_help
      return false
    end
    driver.save_recent_history(args[0])
  end

  def cmd_back_help
    print_line "Usage: back"
    print_line
    print_line "Return to the global dispatcher context"
    print_line
  end

  #
  # Pop the current dispatcher stack context, assuming it isn't pointed at
  # the core or database backend stack context.
  #
  def cmd_back(*args)
    if (driver.dispatcher_stack.size > 1 and
        driver.current_dispatcher.name != 'Core' and
        driver.current_dispatcher.name != 'Database Backend')
      if metasploit_instance
        # setting metasploit_instance automatically destacks the module_type-specific dispatcher and restores the prompt
        # so only have to do that explicitly when going back from a non-metasploit_instance dispatcher.
        self.metasploit_instance = nil
      else
        driver.destack_dispatcher
        driver.restore_prompt
      end
    end
  end

  def cmd_cd_help
    print_line "Usage: cd <directory>"
    print_line
    print_line "Change the current working directory"
    print_line
  end

  #
  # Change the current working directory
  #
  def cmd_cd(*args)
    if(args.length == 0)
      print_error("No path specified")
      return
    end

    begin
      Dir.chdir(args.join(" ").strip)
    rescue ::Exception
      print_error("The specified path does not exist")
    end
  end

  def cmd_banner_help
    print_line "Usage: banner"
    print_line
    print_line "Print a stunning ascii art banner along with version information and module counts"
    print_line
  end

  #
  # Display one of the fabulous banners.
  #
  def cmd_banner(*args)
    banner  = "%cya" + Msf::Ui::Banner.to_s + "%clr\n\n"

    if is_apt
      content = [
        "Large pentest? List, sort, group, tag and search your hosts and services\nin Metasploit Pro -- type 'go_pro' to launch it now.",
        "Frustrated with proxy pivoting? Upgrade to layer-2 VPN pivoting with\nMetasploit Pro -- type 'go_pro' to launch it now.",
        "Save your shells from AV! Upgrade to advanced AV evasion using dynamic\nexe templates with Metasploit Pro -- type 'go_pro' to launch it now.",
        "Easy phishing: Set up email templates, landing pages and listeners\nin Metasploit Pro's wizard -- type 'go_pro' to launch it now.",
        "Using notepad to track pentests? Have Metasploit Pro report on hosts,\nservices, sessions and evidence -- type 'go_pro' to launch it now.",
        "Tired of typing 'set RHOSTS'? Click & pwn with Metasploit Pro\n-- type 'go_pro' to launch it now."
      ]
      banner << content.sample # Ruby 1.9-ism!
      banner << "\n\n"
    end

    banner << "       =[ %yelmetasploit v#{Msf::Framework::Version} [core:#{Msf::Framework::VersionCore} api:#{Msf::Framework::VersionAPI}]%clr\n"
    banner << "+ -- --=[ "
    banner << "#{framework.stats.num_exploits} exploits - #{framework.stats.num_auxiliary} auxiliary - #{framework.stats.num_post} post\n"
    banner << "+ -- --=[ "

    oldwarn = nil
    avdwarn = nil

    banner << "#{framework.stats.num_payloads} payloads - #{framework.stats.num_encoders} encoders - #{framework.stats.num_nops} nops\n"
    if ( ::Msf::Framework::RepoRevision.to_i > 0 and ::Msf::Framework::RepoUpdatedDate)
      tstamp = ::Msf::Framework::RepoUpdatedDate.strftime("%Y.%m.%d")
      banner << "       =[ svn r#{::Msf::Framework::RepoRevision} updated #{::Msf::Framework::RepoUpdatedDaysNote} (#{tstamp})\n"
      if(::Msf::Framework::RepoUpdatedDays > 7)
        oldwarn = []
        oldwarn << "Warning: This copy of the Metasploit Framework was last updated #{::Msf::Framework::RepoUpdatedDaysNote}."
        oldwarn << "         We recommend that you update the framework at least every other day."
        oldwarn << "         For information on updating your copy of Metasploit, please see:"
        oldwarn << "             https://community.rapid7.com/docs/DOC-1306"
        oldwarn << ""
      end
    end

    if ::Msf::Framework::EICARCorrupted
      avdwarn = []
      avdwarn << "Warning: This copy of the Metasploit Framework has been corrupted by an installed anti-virus program."
      avdwarn << "         We recommend that you disable your anti-virus or exclude your Metasploit installation path,"
      avdwarn << "         then restore the removed files from quarantine or reinstall the framework. For more info: "
      avdwarn << "             https://community.rapid7.com/docs/DOC-1273"
      avdwarn << ""
    end

    # Display the banner
    print_line(banner)

    if(oldwarn)
      oldwarn.map{|line| print_line(line) }
    end

    if(avdwarn)
      avdwarn.map{|line| print_error(line) }
    end

  end

  def cmd_connect_help
    print_line "Usage: connect [options] <host> <port>"
    print_line
    print_line "Communicate with a host, similar to interacting via netcat, taking advantage of"
    print_line "any configured session pivoting."
    print @@connect_opts.usage
  end

  #
  # Talk to a host
  #
  def cmd_connect(*args)
    if args.length < 2 or args.include?("-h")
      cmd_connect_help
      return false
    end

    crlf = false
    commval = nil
    fileval = nil
    proxies = nil
    srcaddr = nil
    srcport = nil
    ssl = false
    udp = false
    cto = nil
    justconn = false
    aidx = 0

    @@connect_opts.parse(args) do |opt, idx, val|
      case opt
        when "-C"
          crlf = true
          aidx = idx + 1
        when "-c"
          commval = val
          aidx = idx + 2
        when "-i"
          fileval = val
          aidx = idx + 2
        when "-P"
          srcport = val
          aidx = idx + 2
        when "-p"
          proxies = val
          aidx = idx + 2
        when "-S"
          srcaddr = val
          aidx = idx + 2
        when "-s"
          ssl = true
          aidx = idx + 1
        when "-w"
          cto = val.to_i
          aidx = idx + 2
        when "-u"
          udp = true
          aidx = idx + 1
        when "-z"
          justconn = true
          aidx = idx + 1
      end
    end

    commval = "Local" if commval =~ /local/i

    if fileval
      begin
        raise "Not a file" if File.ftype(fileval) != "file"
        infile = ::File.open(fileval)
      rescue
        print_error("Can't read from '#{fileval}': #{$!}")
        return false
      end
    end

    args = args[aidx .. -1]

    if args.length < 2
      print_error("You must specify a host and port")
      return false
    end

    host = args[0]
    port = args[1]

    comm = nil

    if commval
      begin
        if Rex::Socket::Comm.const_defined?(commval)
          comm = Rex::Socket::Comm.const_get(commval)
        end
      rescue NameError
      end

      if not comm
        session = framework.sessions.get(commval)

        if session.kind_of?(Msf::Session::Comm)
          comm = session
        end
      end

      if not comm
        print_error("Invalid comm '#{commval}' selected")
        return false
      end
    end

    begin
      klass = udp ? ::Rex::Socket::Udp : ::Rex::Socket::Tcp
      sock = klass.create({
        'Comm'      => comm,
        'Proxies'   => proxies,
        'SSL'       => ssl,
        'PeerHost'  => host,
        'PeerPort'  => port,
        'LocalHost' => srcaddr,
        'LocalPort' => srcport,
        'Timeout'   => cto,
        'Context'   => {
          'Msf' => framework
        }
      })
    rescue
      print_error("Unable to connect: #{$!}")
      return false
    end

    print_status("Connected to #{host}:#{port}")

    if justconn
      sock.close
      infile.close if infile
      return true
    end

    cin = infile || driver.input
    cout = driver.output

    begin
      # Console -> Network
      c2n = framework.threads.spawn("ConnectConsole2Network", false, cin, sock) do |input, output|
        while true
          begin
            res = input.gets
            break if not res
            if crlf and (res =~ /^\n$/ or res =~ /[^\r]\n$/)
              res.gsub!(/\n$/, "\r\n")
            end
            output.write res
          rescue ::EOFError, ::IOError
            break
          end
        end
      end

      # Network -> Console
      n2c = framework.threads.spawn("ConnectNetwork2Console", false, sock, cout, c2n) do |input, output, cthr|
        while true
          begin
            res = input.read(65535)
            break if not res
            output.print res
          rescue ::EOFError, ::IOError
            break
          end
        end

        Thread.kill(cthr)
      end

      c2n.join

    rescue ::Interrupt
      c2n.kill
      n2c.kill
    end


    sock.close rescue nil
    infile.close if infile

    true
  end

  #
  # Instructs the driver to stop executing.
  #
  def cmd_exit(*args)
    forced = false
    forced = true if (args[0] and args[0] =~ /-y/i)

    if(framework.sessions.length > 0 and not forced)
      print_status("You have active sessions open, to exit anyway type \"exit -y\"")
      return
    end

    driver.stop
  end

  alias cmd_quit cmd_exit

  def cmd_sleep_help
    print_line "Usage: sleep <seconds>"
    print_line
    print_line "Do nothing the specified number of seconds.  This is useful in rc scripts."
    print_line
  end

  #
  # Causes process to pause for the specified number of seconds
  #
  def cmd_sleep(*args)
    return if not (args and args.length == 1)
    Rex::ThreadSafe.sleep(args[0].to_f)
  end

  def cmd_info_help
    print_line "Usage: info <module name> [mod2 mod3 ...]"
    print_line
    print_line "Queries the supplied module or modules for information. If no module is given,"
    print_line "show info for the currently active module."
    print_line
  end

  #
  # Displays information about one or more module.
  #
  def cmd_info(*args)
    if (args.length == 0)
      if (metasploit_instance)
        print(Serializer::ReadableText.dump_module(metasploit_instance))
        return true
      else
        cmd_info_help
        return false
      end
    elsif args.include? "-h"
      cmd_info_help
      return false
    end

    args.each { |name|
      mod = framework.modules.create(name)

      if (mod == nil)
        print_error("Invalid module: #{name}")
      else
        print(Serializer::ReadableText.dump_module(mod))
      end
    }
  end

  #
  # Tab completion for the info command (same as use)
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_info_tabs(str, words)
    cmd_use_tabs(str, words)
  end

  def cmd_irb_help
    print_line "Usage: irb"
    print_line
    print_line "Drop into an interactive Ruby environment"
    print_line
  end

  #
  # Goes into IRB scripting mode
  #
  def cmd_irb(*args)
    fanged!

    print_status("Starting IRB shell...\n")

    begin
      Rex::Ui::Text::IrbShell.new(binding).run
    rescue
      print_error("Error during IRB: #{$!}\n\n#{$@.join("\n")}")
    end

    # Reset tab completion
    if (driver.input.supports_readline)
      driver.input.reset_tab_completion
    end
  end

  def cmd_jobs_help
    print_line "Usage: jobs [options]"
    print_line
    print_line "Active job manipulation and interaction."
    print @@jobs_opts.usage()
  end

  #
  # Displays and manages running jobs for the active instance of the
  # framework.
  #
  def cmd_jobs(*args)
    # Make the default behavior listing all jobs if there were no options
    # or the only option is the verbose flag
    if (args.length == 0 or args == ["-v"])
      args.unshift("-l")
    end

    verbose = false
    dump_list = false
    dump_info = false
    job_id = nil

    # Parse the command options
    @@jobs_opts.parse(args) { |opt, idx, val|
      case opt
        when "-v"
          verbose = true
        when "-l"
          dump_list = true

        # Terminate the supplied job name
        when "-k"
          if (not framework.jobs.has_key?(val))
            print_error("No such job")
          else
            print_line("Stopping job: #{val}...")
            framework.jobs.stop_job(val)
          end
        when "-K"
          print_line("Stopping all jobs...")
          framework.jobs.each_key do |i|
            framework.jobs.stop_job(i)
          end
        when "-i"
          # Defer printing anything until the end of option parsing
          # so we can check for the verbose flag.
          dump_info = true
          job_id = val
        when "-h"
          cmd_jobs_help
          return false
      end
    }

    if (dump_list)
      print("\n" + Serializer::ReadableText.dump_jobs(framework, verbose) + "\n")
    end
    if (dump_info)
      if (job_id and framework.jobs[job_id.to_s])
        job = framework.jobs[job_id.to_s]
        mod = job.ctx[0]

        output  = "\n"
        output += "Name: #{mod.name}"
        output += ", started at #{job.start_time}" if job.start_time
        print_line(output)

        if (mod.options.has_options?)
          show_options(mod)
        end

        if (verbose)
          mod_opt = Serializer::ReadableText.dump_advanced_options(mod,'   ')
          print_line("\nModule advanced options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)
        end
      else
        print_line("Invalid Job ID")
      end
    end
  end

  #
  # Tab completion for the jobs command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_jobs_tabs(str, words)
    if words.length == 1
      return @@jobs_opts.fmt.keys
    end

    if @@jobs_opts.fmt[words[1]][0] and (words.length == 2)
      return framework.jobs.keys
    end

    []
  end

  def cmd_kill_help
    print_line "Usage: kill <job1> [job2 ...]"
    print_line
    print_line "Equivalent to 'jobs -k job1 -k job2 ...'"
    print @@jobs_opts.usage()
  end

  def cmd_kill(*args)
    cmd_jobs("-k", *args)
  end

  #
  # Tab completion for the kill command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_kill_tabs(str, words)
    return [] if words.length > 1
    framework.jobs.keys
  end

  def cmd_load_help
    print_line "Usage: load <path> [var=val var=val ...]"
    print_line
    print_line "Loads a plugin from the supplied path.  If path is not absolute, fist looks"
    print_line "in the user's plugin directory (#{Msf::Config.user_plugin_directory}) then"
    print_line "in the framework root plugin directory (#{Msf::Config.plugin_directory})."
    print_line "The optional var=val options are custom parameters that can be passed to plugins."
    print_line
  end

  #
  # Loads a plugin from the supplied path.  If no absolute path is supplied,
  # the framework root plugin directory is used.
  #
  def cmd_load(*args)
    fanged!

    if (args.length == 0)
      cmd_load_help
      return false
    end

    # Default to the supplied argument path.
    path = args.shift
    opts  = {
      'LocalInput'    => driver.input,
      'LocalOutput'   => driver.output,
      'ConsoleDriver' => driver
      }

    # Parse any extra options that should be passed to the plugin
    args.each { |opt|
      k, v = opt.split(/\=/)

      opts[k] = v if (k and v)
    }

    # If no absolute path was supplied, check the base and user plugin directories
    if (path !~ /#{File::SEPARATOR}/)
      plugin_file_name = path

      # If the plugin isn't in the user directory (~/.msf3/plugins/), use the base
      path = Msf::Config.user_plugin_directory + File::SEPARATOR + plugin_file_name
      if not File.exists?( path  + ".rb" )
        # If the following "path" doesn't exist it will be caught when we attempt to load
        path = Msf::Config.plugin_directory + File::SEPARATOR + plugin_file_name
      end

    end

    # Load that plugin!
    begin
      if (inst = framework.plugins.load(path, opts))
        print_status("Successfully loaded plugin: #{inst.name}")
      end
    rescue ::Exception => e
      elog("Error loading plugin #{path}: #{e}\n\n#{e.backtrace.join("\n")}", src = 'core', level = 0, from = caller)
      print_error("Failed to load plugin from #{path}: #{e}")
    end
  end

  #
  # Tab completion for the load command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_load_tabs(str, words)
    tabs = []

    if (not words[1] or not words[1].match(/^\//))
      # then let's start tab completion in the scripts/resource directories
      begin
        [
          Msf::Config.user_plugin_directory,
          Msf::Config.plugin_directory
        ].each do |dir|
          next if not ::File.exist? dir
          tabs += ::Dir.new(dir).find_all { |e|
            path = dir + File::SEPARATOR + e
            ::File.file?(path) and File.readable?(path)
          }
        end
      rescue Exception
      end
    else
      tabs += tab_complete_filenames(str,words)
    end
    return tabs.map{|e| e.sub(/.rb/, '')}

  end

  def cmd_route_help
    print_line "Usage: route [add/remove/get/flush/print] subnet netmask [comm/sid]"
    print_line
    print_line "Route traffic destined to a given subnet through a supplied session."
    print_line "The default comm is Local."
    print_line
  end

  #
  # This method handles the route command which allows a user to specify
  # which session a given subnet should route through.
  #
  def cmd_route(*args)
    if (args.length == 0)
      cmd_route_help
      return false
    end

    arg = args.shift
    case arg

    when "add", "remove", "del"
      if (args.length < 3)
        print_error("Missing arguments to route #{arg}.")
        return false
      end

      # Satisfy check to see that formatting is correct
      unless Rex::Socket::RangeWalker.new(args[0]).length == 1
        print_error "Invalid IP Address"
        return false
      end

      unless Rex::Socket::RangeWalker.new(args[1]).length == 1
        print_error "Invalid Subnet mask"
        return false
      end

      gw = nil

      # Satisfy case problems
      args[2] = "Local" if (args[2] =~ /local/i)

      begin
        # If the supplied gateway is a global Comm, use it.
        if (Rex::Socket::Comm.const_defined?(args[2]))
          gw = Rex::Socket::Comm.const_get(args[2])
        end
      rescue NameError
      end

      # If we still don't have a gateway, check if it's a session.
      if ((gw == nil) and
          (session = framework.sessions.get(args[2])) and
          (session.kind_of?(Msf::Session::Comm)))
        gw = session
      elsif (gw == nil)
        print_error("Invalid gateway specified.")
        return false
      end

      if arg == "remove" or arg == "del"
        worked = Rex::Socket::SwitchBoard.remove_route(args[0], args[1], gw)
        if worked
          print_status("Route removed")
        else
          print_error("Route not found")
        end
      else
        worked = Rex::Socket::SwitchBoard.add_route(args[0], args[1], gw)
        if worked
          print_status("Route added")
        else
          print_error("Route already exists")
        end
      end

    when "get"
      if (args.length == 0)
        print_error("You must supply an IP address.")
        return false
      end

      comm = Rex::Socket::SwitchBoard.best_comm(args[0])

      if ((comm) and
          (comm.kind_of?(Msf::Session)))
        print_line("#{args[0]} routes through: Session #{comm.sid}")
      else
        print_line("#{args[0]} routes through: Local")
      end


    when "flush"
      Rex::Socket::SwitchBoard.flush_routes

    when "print"
      tbl =	Table.new(
        Table::Style::Default,
        'Header'  => "Active Routing Table",
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' =>
          [
            'Subnet',
            'Netmask',
            'Gateway',
          ],
        'ColProps' =>
          {
            'Subnet'  => { 'MaxWidth' => 17 },
            'Netmask' => { 'MaxWidth' => 17 },
          })

      Rex::Socket::SwitchBoard.each { |route|

        if (route.comm.kind_of?(Msf::Session))
          gw = "Session #{route.comm.sid}"
        else
          gw = route.comm.name.split(/::/)[-1]
        end

        tbl << [ route.subnet, route.netmask, gw ]
      }

      print(tbl.to_s)
    else
      cmd_route_help
    end
  end

  #
  # Tab completion for the route command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_route_tabs(str, words)
    if words.length == 1
      return %w{add remove get flush print}
    end

    ret = []
    case words[1]
    when "remove", "del"
      Rex::Socket::SwitchBoard.each { |route|
        case words.length
        when 2
          ret << route.subnet
        when 3
          if route.subnet == words[2]
            ret << route.netmask
          end
        when 4
          if route.subnet == words[2]
            ret << route.comm.sid.to_s if route.comm.kind_of? Msf::Session
          end
        end
      }
      ret
    when "add"
      # We can't really complete the subnet and netmask args without
      # diving pretty deep into all sessions, so just be content with
      # completing sids for the last arg
      if words.length == 4
        ret = framework.sessions.keys.map { |k| k.to_s }
      end
    # The "get" command takes one arg, but we can't complete it either...
    end

    ret
  end

  def cmd_save_help
    print_line "Usage: save"
    print_line
    print_line "Save the active datastore contents to disk for automatic use across restarts of the console"
    print_line
    print_line "The configuration is stored in #{Msf::Config.config_file}"
    print_line
  end

  #
  # Saves the active datastore contents to disk for automatic use across
  # restarts of the console.
  #
  def cmd_save(*args)
    fanged!

    # Save the console config
    driver.save_config

    # Save the framework's datastore
    begin
      framework.save_config

      if (metasploit_instance)
        metasploit_instance.save_config
      end
    rescue
      log_error("Save failed: #{$!}")
      return false
    end

    print_line("Saved configuration to: #{Msf::Config.config_file}")
  end

  def cmd_loadpath_help
    print_line "Usage: loadpath </path/to/modules>"
    print_line
    print_line "Loads modules from the given directory which should contain subdirectories for"
    print_line "module types, e.g. /path/to/modules/exploits"
    print_line
  end

  #
  # Adds one or more search paths.
  #
  def cmd_loadpath(*args)
    fanged!

    if (args.length == 0 or args.include? "-h")
      cmd_loadpath_help
      return true
    end

    totals    = {}
    overall   = 0
    curr_path = nil

    begin
      # Walk the list of supplied search paths attempting to add each one
      # along the way
      args.each { |path|
        curr_path = path

        # Load modules, but do not consult the cache
        if (counts = framework.modules.add_path(path))
          counts.each_pair { |type, count|
            totals[type] = (totals[type]) ? (totals[type] + count) : count

            overall += count
          }
        end
      }
    rescue NameError, RuntimeError
      log_error("Failed to add search path #{curr_path}: #{$!}")
      return true
    end

    added = "Loaded #{overall} modules:\n"

    totals.each_pair { |type, count|
      added << "    #{count} #{type}#{count != 1 ? 's' : ''}\n"
    }

    print(added)
  end

  #
  # Tab completion for the loadpath command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_loadpath_tabs(str, words)
    return [] if words.length > 1

    # This custom completion might better than Readline's... We'll leave it for now.
    #tab_complete_filenames(str,words)

    paths = []
    if (File.directory?(str))
      paths = Dir.entries(str)
      paths = paths.map { |f|
        if File.directory? File.join(str,f)
          File.join(str,f)
        end
      }
      paths.delete_if { |f| f.nil? or File.basename(f) == '.' or File.basename(f) == '..' }
    else
      d = Dir.glob(str + "*").map { |f| f if File.directory?(f) }
      d.delete_if { |f| f.nil? or f == '.' or f == '..' }
      # If there's only one possibility, descend to the next level
      if (1 == d.length)
        paths = Dir.entries(d[0])
        paths = paths.map { |f|
          if File.directory? File.join(d[0],f)
            File.join(d[0],f)
          end
        }
        paths.delete_if { |f| f.nil? or File.basename(f) == '.' or File.basename(f) == '..' }
      else
        paths = d
      end
    end
    paths.sort!
    return paths
  end

  def cmd_sessions_help
    print_line "Usage: sessions [options]"
    print_line
    print_line "Active session manipulation and interaction."
    print(@@sessions_opts.usage())
  end

  #
  # Provides an interface to the sessions currently active in the framework.
  #
  def cmd_sessions(*args)
    begin
    method  = nil
    quiet   = false
    verbose = false
    sid     = nil
    cmds    = []
    script  = nil
    reset_ring = false

    # any arguments that don't correspond to an option or option arg will
    # be put in here
    extra   = []

    # Parse the command options
    @@sessions_opts.parse(args) { |opt, idx, val|
      case opt
        when "-q"
          quiet = true

        # Run a command on all sessions, or the session given with -i
        when "-c"
          method = 'cmd'
          if (val)
            cmds << val
          end

        when "-v"
          verbose = true

        # Do something with the supplied session identifier instead of
        # all sessions.
        when "-i"
          sid = val

        # Display the list of active sessions
        when "-l"
          method = 'list'

        when "-k"
          method = 'kill'
          sid = val if val
          if not sid
            print_error("Specify a session to kill")
            return false
          end

        when "-K"
          method = 'killall'

        when "-d"
          method = 'detach'
          sid = val

        # Run a script on all meterpreter sessions
        when "-s"
          if  not script
            method = 'scriptall'
            script = val
          end

        # Upload and exec to the specific command session
        when "-u"
          method = 'upexec'
          sid = val

        # Reset the ring buffer read pointer
        when "-r"
          reset_ring = true
          method = 'reset_ring'

        # Display help banner
        when "-h"
          cmd_sessions_help
          return false
        else
          extra << val
      end
    }

    if sid and not framework.sessions.get(sid)
      print_error("Invalid session id")
      return false
    end

    if method.nil? and sid
      method = 'interact'
    end

    # Now, perform the actual method
    case method

      when 'cmd'
        if (cmds.length < 1)
          print_error("No command specified!")
          return false
        end
        cmds.each do |cmd|
          if sid
            sessions = [ sid ]
          else
            sessions = framework.sessions.keys.sort
          end
          sessions.each do |s|
            session = framework.sessions.get(s)
            print_status("Running '#{cmd}' on #{session.type} session #{s} (#{session.session_host})")

            if (session.type == "meterpreter")
              # If session.sys is nil, dont even try..
              if not (session.sys)
                print_error("Session #{s} does not have stdapi loaded, skipping...")
                next
              end
              c, c_args = cmd.split(' ', 2)
              begin
                process = session.sys.process.execute(c, c_args,
                  {
                    'Channelized' => true,
                    'Hidden'      => true
                  })
              rescue ::Rex::Post::Meterpreter::RequestError
                print_error("Failed: #{$!.class} #{$!}")
              end
              if process and process.channel and (data = process.channel.read)
                print_line(data)
              end
            elsif session.type == "shell"
              if (output = session.shell_command(cmd))
                print_line(output)
              end
            end
            # If the session isn't a meterpreter or shell type, it
            # could be a VNC session (which can't run commands) or
            # something custom (which we don't know how to run
            # commands on), so don't bother.
          end
        end

      when 'kill'
        if ((session = framework.sessions.get(sid)))
          print_status("Killing session #{sid}")
          session.kill
        else
          print_error("Invalid session identifier: #{sid}")
        end

      when 'killall'
        print_status("Killing all sessions...")
        framework.sessions.each_sorted do |s|
          if ((session = framework.sessions.get(s)))
            session.kill
          end
        end

      when 'detach'
        if ((session = framework.sessions.get(sid)))
          print_status("Detaching session #{sid}")
          if (session.interactive?)
            session.detach()
          end
        else
          print_error("Invalid session identifier: #{sid}")
        end

      when 'interact'
        if ((session = framework.sessions.get(sid)))
          if (session.interactive?)
            print_status("Starting interaction with #{session.name}...\n") if (quiet == false)

            self.active_session = session

            session.interact(driver.input.dup, driver.output)

            self.active_session = nil

            if (driver.input.supports_readline)
              driver.input.reset_tab_completion
            end

          else
            print_error("Session #{sid} is non-interactive.")
          end
        else
          print_error("Invalid session identifier: #{sid}")
        end

      when 'scriptall'
        if (script.nil?)
          print_error("No script specified!")
          return false
        end

        script_paths = {}
        script_paths['meterpreter'] = Msf::Sessions::Meterpreter.find_script_path(script)
        script_paths['shell'] = Msf::Sessions::CommandShell.find_script_path(script)

        if sid
          print_status("Running script #{script} on session #{sid}...")
          sessions = [ sid ]
        else
          print_status("Running script #{script} on all sessions...")
          sessions = framework.sessions.keys.sort
        end

        sessions.each do |s|
          if ((session = framework.sessions.get(s)))
            if (script_paths[session.type])
              print_status("Session #{s} (#{session.session_host}):")
              begin
                session.execute_file(script_paths[session.type], extra)
              rescue ::Exception => e
                log_error("Error executing script: #{e.class} #{e}")
              end
            end
          end
        end

      when 'upexec'
        if ((session = framework.sessions.get(sid)))
          if (session.interactive?)
            if (session.type == "shell") # XXX: check for windows?
              session.init_ui(driver.input, driver.output)
              session.execute_script('spawn_meterpreter', nil)
              session.reset_ui
            else
              print_error("Session #{sid} is not a command shell session.")
            end
          else
            print_error("Session #{sid} is non-interactive.")
          end
        else
          print_error("Invalid session identifier: #{sid}")
        end

      when 'reset_ring'
        sessions = sid ? [ sid ] : framework.sessions.keys
        sessions.each do |sidx|
          s = framework.sessions[sidx]
          next if not (s and s.respond_to?(:ring_seq))
          s.reset_ring_sequence
          print_status("Reset the ring buffer pointer for Session #{sidx}")
        end

      when 'list',nil
        print_line
        print(Serializer::ReadableText.dump_sessions(framework, :verbose => verbose))
        print_line
    end

    rescue IOError, EOFError, Rex::StreamClosedError
      print_status("Session stream closed.")
    rescue ::Interrupt
      raise $!
    rescue ::Exception
      log_error("Session manipulation failed: #{$!} #{$!.backtrace.inspect}")
    end

    # Reset the active session
    self.active_session = nil

    return true
  end

  #
  # Tab completion for the sessions command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_sessions_tabs(str, words)
    if words.length == 1
      return @@sessions_opts.fmt.keys
    end

    case words[-1]
    when "-i", "-k", "-d", "-u"
      return framework.sessions.keys.map { |k| k.to_s }

    when "-c"
      # Can't really complete commands hehe

    when "-s"
      # XXX: Complete scripts

    end

    []
  end

  def cmd_set_help
    print_line "Usage: set [option] [value]"
    print_line
    print_line "Set the given option to value.  If value is omitted, print the current value."
    print_line "If both are omitted, print options that are currently set."
    print_line
    print_line "If run from a module context, this will set the value in the module's"
    print_line "datastore.  Use -g to operate on the global datastore"
    print_line
  end

  #
  # Sets a name to a value in a context aware environment.
  #
  def cmd_set(*args)

    # Figure out if these are global variables
    global = false

    if (args[0] == '-g')
      args.shift
      global = true
    end

    # Decide if this is an append operation
    append = false

    if (args[0] == '-a')
      args.shift
      append = true
    end

    # Determine which data store we're operating on
    if (metasploit_instance and global == false)
      datastore = metasploit_instance.datastore
    else
      global = true
      datastore = self.framework.datastore
    end

    # Dump the contents of the active datastore if no args were supplied
    if (args.length == 0)
      # If we aren't dumping the global data store, then go ahead and
      # dump it first
      if (!global)
        print("\n" +
          Msf::Serializer::ReadableText.dump_datastore(
            "Global", framework.datastore))
      end

      # Dump the active datastore
      print("\n" +
        Msf::Serializer::ReadableText.dump_datastore(
          (global) ? "Global" : "Module: #{metasploit_instance.refname}",
          datastore) + "\n")
      return true
    elsif (args.length == 1)
      if (not datastore[args[0]].nil?)
        print_line("#{args[0]} => #{datastore[args[0]]}")
        return true
      else
        print_error("Unknown variable")
        cmd_set_help
        return false
      end
    end

    # Set the supplied name to the supplied value
    name  = args[0]
    value = args[1, args.length-1].join(' ')
    if (name.upcase == "TARGET")
      # Different targets can have different architectures and platforms
      # so we need to rebuild the payload list whenever the target
      # changes.
      @cache_payloads = nil
    end

    # Security check -- make sure the data store element they are setting
    # is not prohibited
    if global and Msf::Ui::Console::Driver::DEFANGED_PROHIBITED_DATA_STORE_ELEMENTS.include?(name)
      fanged!
    end

    # If the driver indicates that the value is not valid, bust out.
    if (driver.on_variable_set(global, name, value) == false)
      print_error("The value specified for #{name} is not valid.")
      return true
    end

    if append
      datastore[name] = datastore[name] + value
    else
      datastore[name] = value
    end

    print_line("#{name} => #{datastore[name]}")
  end

  #
  # Tab completion for the set command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_set_tabs(str, words)

    # A value has already been specified
    return [] if words.length > 2

    # A value needs to be specified
    if words.length == 2
      return tab_complete_option(str, words)
    end

    res = cmd_unset_tabs(str, words) || [ ]
    # There needs to be a better way to register global options, but for
    # now all we have is an ad-hoc list of opts that the shell treats
    # specially.
    res += %w{
      ConsoleLogging
      LogLevel
      MinimumRank
      SessionLogging
      TimestampOutput
      Prompt
      PromptChar
      PromptTimeFormat
    }
    mod = metasploit_instance

    if (not mod)
      return res
    end

    mod.options.sorted.each { |e|
      name, opt = e
      res << name
    }

    # Exploits provide these three default options
    if (mod.exploit?)
      res << 'PAYLOAD'
      res << 'NOP'
      res << 'TARGET'
    end
    if (mod.exploit? or mod.payload?)
      res << 'ENCODER'
    end

    if (mod.auxiliary?)
      res << "ACTION"
    end

    if (mod.exploit? and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])
      if (p)
        p.options.sorted.each { |e|
          name, opt = e
          res << name
        }
      end
    end

    return res
  end

  def cmd_setg_help
    print_line "Usage: setg [option] [value]"
    print_line
    print_line "Exactly like set -g, set a value in the global datastore."
    print_line
  end

  #
  # Sets the supplied variables in the global datastore.
  #
  def cmd_setg(*args)
    args.unshift('-g')

    cmd_set(*args)
  end

  #
  # Tab completion for the setg command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_setg_tabs(str, words)
    cmd_set_tabs(str, words)
  end

  def cmd_show_help
    global_opts = %w{all encoders nops exploits payloads auxiliary plugins options}
    print_status("Valid parameters for the \"show\" command are: #{global_opts.join(", ")}")

    module_opts = %w{ advanced evasion targets actions }
    print_status("Additional module-specific parameters are: #{module_opts.join(", ")}")
  end

  #
  # Displays the list of modules based on their type, or all modules if
  # no type is provided.
  #
  def cmd_show(*args)
    mod = self.metasploit_instance

    args << "all" if (args.length == 0)

    args.each { |type|
      case type
        when '-h'
          cmd_show_help
        when 'all'
          show_encoders
          show_nops
          show_exploits
          show_payloads
          show_auxiliary
          show_post
          show_plugins
        when 'encoders'
          show_encoders
        when 'nops'
          show_nops
        when 'exploits'
          show_exploits
        when 'payloads'
          show_payloads
        when 'auxiliary'
          show_auxiliary
        when 'post'
          show_post
        when 'options'
          if (mod)
            show_options(mod)
          else
            show_global_options
          end
        when 'advanced'
          if (mod)
            show_advanced_options(mod)
          else
            print_error("No module selected.")
          end
        when 'evasion'
          if (mod)
            show_evasion_options(mod)
          else
            print_error("No module selected.")
          end
        when 'sessions'
          if (metasploit_instance and metasploit_instance.respond_to?(:compatible_sessions))
            sessions = metasploit_instance.compatible_sessions
          else
            sessions = framework.sessions.keys.sort
          end
          print_line
          print(Serializer::ReadableText.dump_sessions(framework, :session_ids => sessions))
          print_line
        when "plugins"
          show_plugins
        when "targets"
          if (mod and mod.exploit?)
            show_targets(mod)
          else
            print_error("No exploit module selected.")
          end
        when "actions"
          if (mod and (mod.auxiliary? or mod.post?))
            show_actions(mod)
          else
            print_error("No auxiliary module selected.")
          end

        else
          print_error("Invalid parameter \"#{type}\", use \"show -h\" for more information")
      end
    }
  end

  #
  # Tab completion for the show command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_show_tabs(str, words)
    return [] if words.length > 1

    res = %w{all encoders nops exploits payloads auxiliary post plugins options}
    if (metasploit_instance)
      res.concat(%w{ advanced evasion targets actions })
      if (metasploit_instance.respond_to? :compatible_sessions)
        res << "sessions"
      end
    end
    return res
  end

  def cmd_unload_help
    print_line "Usage: unload <plugin name>"
    print_line
    print_line "Unloads a plugin by its symbolic name.  Use 'show plugins' to see a list of"
    print_line "currently loaded plugins."
    print_line
  end

  #
  # Unloads a plugin by its name.
  #
  def cmd_unload(*args)
    if (args.length == 0)
      cmd_unload_help
      return false
    end

    # Walk the plugins array
    framework.plugins.each { |plugin|
      # Unload the plugin if it matches the name we're searching for
      if (plugin.name == args[0])
        print("Unloading plugin #{args[0]}...")
        framework.plugins.unload(plugin)
        print_line("unloaded.")
        break
      end
    }
  end

  #
  # Tab completion for the unload command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_unload_tabs(str, words)
    return [] if words.length > 1

    tabs = []
    framework.plugins.each { |k| tabs.push(k.name) }
    return tabs
  end

  def cmd_unset_help
    print_line "Usage: unset [-g] var1 var2 var3 ..."
    print_line
    print_line "The unset command is used to unset one or more variables."
    print_line "To flush all entires, specify 'all' as the variable name."
    print_line "With -g, operates on global datastore variables."
    print_line
  end

  #
  # Unsets a value if it's been set.
  #
  def cmd_unset(*args)

    # Figure out if these are global variables
    global = false

    if (args[0] == '-g')
      args.shift
      global = true
    end

    # Determine which data store we're operating on
    if (metasploit_instance and global == false)
      datastore = metasploit_instance.datastore
    else
      datastore = framework.datastore
    end

    # No arguments?  No cookie.
    if (args.length == 0)
      cmd_unset_help
      return false
    end

    # If all was specified, then flush all of the entries
    if args[0] == 'all'
      print_line("Flushing datastore...")

      # Re-import default options into the module's datastore
      if (metasploit_instance and global == false)
        metasploit_instance.import_defaults
      # Or simply clear the global datastore
      else
        datastore.clear
      end

      return true
    end

    while ((val = args.shift))
      if (driver.on_variable_unset(global, val) == false)
        print_error("The variable #{val} cannot be unset at this time.")
        next
      end

      print_line("Unsetting #{val}...")

      datastore.delete(val)
    end
  end

  #
  # Tab completion for the unset command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_unset_tabs(str, words)
    datastore = metasploit_instance ? metasploit_instance.datastore : self.framework.datastore
    datastore.keys
  end

  def cmd_unsetg_help
    print_line "Usage: unsetg var1 [var2 ...]"
    print_line
    print_line "Exactly like unset -g, unset global variables, or all"
    print_line
  end

  #
  # Unsets variables in the global data store.
  #
  def cmd_unsetg(*args)
    args.unshift('-g')

    cmd_unset(*args)
  end

  #
  # Tab completion for the unsetg command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_unsetg_tabs(str, words)
    self.framework.datastore.keys
  end

  alias cmd_unsetg_help cmd_unset_help

  #
  # Command to take to the previously active module
  #
  def cmd_previous()
    if @module_class_full_name_was
      cmd_use(@module_class_full_name_was)
    else
      print_error("There isn't a previous module at the moment")
    end
  end

  #
  # Help for the 'previous' command
  #
  def cmd_previous_help
    print_line "Usage: previous"
    print_line
    print_line "Set the previously loaded module as the current module"
    print_line
  end

  #
  # Command to enqueque a module on the module stack
  #
  def cmd_pushm(*args)
    # could check if each argument is a valid module, but for now let them hang themselves
    if args.count > 0
      args.each do |arg|
        @module_name_stack.push(arg)
        # Note new modules are appended to the array and are only module (full)names
      end
    else #then just push the active module
      if metasploit_instance
        #print_status "Pushing the active module"
        @module_name_stack.push(metasploit_instance.fullname)
      else
        print_error("There isn't an active module and you didn't specify a module to push")
        return self.cmd_pushm_help
      end
    end
  end

  #
  # Tab completion for the pushm command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_pushm_tabs(str, words)
    tab_complete_module(str, words)
  end

  #
  # Help for the 'pushm' command
  #
  def cmd_pushm_help
    print_line "Usage: pushm [module1 [,module2, module3...]]"
    print_line
    print_line "push current active module or specified modules onto the module stack"
    print_line
  end

  #
  # Command to dequeque a module from the module stack
  #
  def cmd_popm(*args)
    if (args.count > 1 or not args[0].respond_to?("to_i"))
      return self.cmd_popm_help
    elsif args.count == 1
      # then pop 'n' items off the stack, but don't change the active module
      if args[0].to_i >= @module_name_stack.count
        # in case they pass in a number >= the length of @module_name_stack
        @module_name_stack = []
        print_status("The module stack is empty")
      else
        @module_name_stack.pop[args[0]]
      end
    else #then just pop the array and make that the active module
      pop = @module_name_stack.pop
      if pop
        return self.cmd_use(pop)
      else
        print_error("There isn't anything to pop, the module stack is empty")
      end
    end
  end

  #
  # Help for the 'popm' command
  #
  def cmd_popm_help
    print_line "Usage: popm [n]"
    print_line
    print_line "pop the latest module off of the module stack and make it the active module"
    print_line "or pop n modules off the stack, but don't change the active module"
    print_line
  end

  #
  # Returns the revision of the framework and console library
  #
  def cmd_version(*args)
    svn_console_version = "$Revision: 15168 $"
    svn_metasploit_version = Msf::Framework::Revision.match(/ (.+?) \$/)[1] rescue nil
    if svn_metasploit_version
      print_line("Framework: #{Msf::Framework::Version}.#{svn_metasploit_version}")
    else
      print_line("Framework: #{Msf::Framework::Version}")
    end
    print_line("Console  : #{Msf::Framework::Version}.#{svn_console_version.match(/ (.+?) \$/)[1]}")

    return true
  end

  def cmd_grep_help
    print_line "Usage: grep [options] pattern cmd"
    print_line
    print_line "Grep the results of a console command (similar to Linux grep command)"
    print(@@grep_opts.usage())
  end

  #
  # Greps the output of another console command, usage is similar the shell grep command
  # grep [options] pattern other_cmd [other command's args], similar to the shell's grep [options] pattern file
  # however it also includes -k to keep lines and -s to skip lines.  grep -k 5 is useful for keeping table headers
  #
  # @param args [Array<String>] Args to the grep command minimally including a pattern & a command to search
  # @return [String,nil] Results matching the regular expression given

  def cmd_grep(*args)
    return cmd_grep_help if args.length < 2
    match_mods = {:insensitive => false}
    output_mods = {:count => false, :invert => false}
    @@grep_opts.parse(args.dup) do |opt, idx, val|
      case opt
        when "-h"
          return cmd_grep_help
        when "-m"
          # limit to arg matches
          match_mods[:max] = val.to_i
          # delete opt and val from args list
          args.shift(2)
        when "-A"
          # also return arg lines after a match
          output_mods[:after] = val.to_i
          # delete opt and val from args list
          args.shift(2)
        when "-B"
          # also return arg lines before a match
          output_mods[:before] = val.to_i
          # delete opt and val from args list
          args.shift(2)
        when "-v"
          # invert match
          match_mods[:invert] = true
          # delete opt from args list
          args.shift
        when "-i"
          # case insensitive
          match_mods[:insensitive] = true
          args.shift
        when "-c"
          # just count matches
          output_mods[:count] = true
          args.shift
        when "-k"
          # keep arg number of lines at the top of the output, useful for commands with table headers in output
          output_mods[:keep] = val.to_i
          args.shift(2)
        when "-s"
          # skip arg number of lines at the top of the output, useful for avoiding undesirable matches
          output_mods[:skip] = val.to_i
          args.shift(2)
      end
    end
    # after deleting parsed options, the only args left should be the pattern, the cmd to run, and cmd args
    pattern = args.shift
    if match_mods[:insensitive]
      rx = Regexp.new(pattern, true)
    else
      rx = Regexp.new(pattern)
    end
    cmd = args.join(" ")

    # get a ref to the current console driver
    orig_driver = self.driver
    # redirect output after saving the old ones and getting a new output buffer to use for redirect
    orig_driver_output = orig_driver.output
    orig_driver_input = orig_driver.input

    # we use a rex buffer but add a write method to the instance, which is
    # required in order to be valid $stdout
    temp_output = Rex::Ui::Text::Output::Buffer.new
    temp_output.extend Rex::Ui::Text::Output::Buffer::Stdout

    orig_driver.init_ui(orig_driver_input,temp_output)
    # run the desired command to be grepped
    orig_driver.run_single(cmd)
    # restore original output
    orig_driver.init_ui(orig_driver_input,orig_driver_output)

    # restore the prompt so we don't get "msf >  >".
    prompt = framework_prompt.to_s

    if active_module # if there is an active module, give them the fanciness they have come to expect
      prompt += " #{active_module.type}(%bld%red#{active_module.shortname}%clr)"
    end

    driver.update_prompt(prompt, framework_prompt_char, true)

    # dump the command's output so we can grep it
    cmd_output = temp_output.dump_buffer

    # Bail if the command failed
    if cmd_output =~ /Unknown command:/
      print_error("Unknown command: #{args[0]}.")
      return false
    end
    # put lines into an array so we can access them more easily and split('\n') doesn't work on the output obj.
    all_lines = cmd_output.lines.select {|line| line}
    # control matching based on remaining match_mods (:insensitive was already handled)
    if match_mods[:invert]
      statement = 'not line =~ rx'
    else
      statement = 'line =~ rx'
    end

    our_lines = []
    count = 0
    all_lines.each_with_index do |line, line_num|
      next if (output_mods[:skip] and line_num < output_mods[:skip])
      our_lines << line if (output_mods[:keep] and line_num < output_mods[:keep])
      # we don't wan't to keep processing if we have a :max and we've reached it already (not counting skips/keeps)
      break if match_mods[:max] and count >= match_mods[:max]
      if eval statement
        count += 1
        # we might get a -A/after and a -B/before at the same time
        our_lines += retrieve_grep_lines(all_lines,line_num,output_mods[:before], output_mods[:after])
      end
    end

    # now control output based on remaining output_mods such as :count
    return print_status(count.to_s) if output_mods[:count]
    our_lines.each {|line| print line}
  end

  #
  # Tab completion for the grep command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_grep_tabs(str, words)
    tabs = @@grep_opts.fmt.keys || [] # default to use grep's options
    # if not an opt, use normal tab comp.
    # @todo uncomment out next line when tab_completion normalization is complete RM7649 or
    # replace with new code that permits "nested" tab completion
    # tabs = driver.get_all_commands if (str and str =~ /\w/)
    tabs
  end

  #
  # Tab complete module names
  #
  def tab_complete_module(str, words)
    res = []
    framework.modules.module_types.each do |mtyp|
      mset = framework.modules.module_names(mtyp)
      mset.each do |mref|
        res << mtyp + '/' + mref
      end
    end

    return res.sort
  end


  #
  # Provide tab completion for option values
  #
  def tab_complete_option(str, words)
    opt = words[1]
    res = []
    mod = metasploit_instance

    # With no active module, we have nothing to compare
    if (not mod)
      return res
    end

    # Well-known option names specific to exploits
    if (mod.exploit?)
      return option_values_payloads() if opt.upcase == 'PAYLOAD'
      return option_values_targets()  if opt.upcase == 'TARGET'
      return option_values_nops()     if opt.upcase == 'NOPS'
      return option_values_encoders() if opt.upcase == 'StageEncoder'
    end

    # Well-known option names specific to auxiliaries
    if (mod.auxiliary?)
      return option_values_actions() if opt.upcase == 'ACTION'
    end

    # The ENCODER option works for payloads and exploits
    if ((mod.exploit? or mod.payload?) and opt.upcase == 'ENCODER')
      return option_values_encoders()
    end

    # Well-known option names specific to post-exploitation
    if (mod.post? or mod.exploit?)
      return option_values_sessions() if opt.upcase == 'SESSION'
    end

    # Is this option used by the active module?
    if (mod.options.include?(opt))
      res.concat(option_values_dispatch(mod.options[opt], str, words))
    end

    # How about the selected payload?
    if (mod.exploit? and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])
      if (p and p.options.include?(opt))
        res.concat(option_values_dispatch(p.options[opt], str, words))
      end
    end

    return res
  end

  #
  # Provide possible option values based on type
  #
  def option_values_dispatch(o, str, words)

    res = []
    res << o.default.to_s if o.default

    case o.class.to_s

      when 'Msf::OptAddress'
        case o.name.upcase
          when 'RHOST'
            option_values_target_addrs().each do |addr|
              res << addr
            end
          when 'LHOST'
            rh = self.metasploit_instance.datastore["RHOST"]
            if rh and not rh.empty?
              res << Rex::Socket.source_address(rh)
            else
              res << Rex::Socket.source_address()
            end
          else
        end

      when 'Msf::OptAddressRange'

        case str
          when /\/$/
            res << str+'32'
            res << str+'24'
            res << str+'16'
          when /\-$/
            res << str+str[0, str.length - 1]
          else
            option_values_target_addrs().each do |addr|
              res << addr+'/32'
              res << addr+'/24'
              res << addr+'/16'
            end
        end

      when 'Msf::OptPort'
        case o.name.upcase
          when 'RPORT'
          option_values_target_ports().each do |port|
            res << port
          end
        end

        if (res.empty?)
          res << (rand(65534)+1).to_s
        end

      when 'Msf::OptEnum'
        o.enums.each do |val|
          res << val
        end
      when 'Msf::OptPath'
        files = tab_complete_filenames(str,words)
        res += files if files
    end

    return res
  end

  #
  # Provide valid payload options for the current exploit
  #
  def option_values_payloads
    return @cache_payloads if @cache_payloads

    @cache_payloads = metasploit_instance.compatible_payloads.map { |refname, payload|
      refname
    }

    @cache_payloads
  end

  #
  # Provide valid session options for the current post-exploit module
  #
  def option_values_sessions
    metasploit_instance.compatible_sessions.map { |sid| sid.to_s }
  end

  #
  # Provide valid target options for the current exploit
  #
  def option_values_targets
    res = []
    if (metasploit_instance.targets)
      1.upto(metasploit_instance.targets.length) { |i| res << (i-1).to_s }
    end
    return res
  end


  #
  # Provide valid action options for the current auxiliary module
  #
  def option_values_actions
    res = []
    if (metasploit_instance.actions)
      metasploit_instance.actions.each { |i| res << i.name }
    end
    return res
  end

  #
  # Provide valid nops options for the current exploit
  #
  def option_values_nops
    framework.nops.map { |refname, mod| refname }
  end

  #
  # Provide valid encoders options for the current exploit or payload
  #
  def option_values_encoders
    framework.encoders.map { |refname, mod| refname }
  end

  #
  # Provide the target addresses
  #
  def option_values_target_addrs
    res = [ ]
    res << Rex::Socket.source_address()

    framework.db.with_connection do
      # List only those hosts with matching open ports?
      mport = self.metasploit_instance.datastore['RPORT']
      if (mport)
        mport = mport.to_i
        hosts = {}
        framework.db.each_service(framework.db.workspace) do |service|
          if (service.port == mport)
            hosts[ service.host.address ] = true
          end
        end

        hosts.keys.each do |host|
          res << host
        end

        # List all hosts in the database
      else
        framework.db.each_host(framework.db.workspace) do |host|
          res << host.address
        end
      end
    end

    return res
  end

  #
  # Provide the target ports
  #
  def option_values_target_ports
    res = [ ]
    rhost = self.metasploit_instance.datastore['RHOST']

    unless rhost
      framework.db.with_connection do
        host = framework.db.has_host?(framework.db.workspace, rhost)

        if host
          framework.db.each_service(framework.db.workspace) do |service|
            if (service.host_id == host.id)
              res << service.port.to_s
            end
          end
        end
      end
    end

    return res
  end

  def cmd_go_pro_help
    print_line "Usage: go_pro"
    print_line
    print_line "Launch the Metasploit web GUI"
    print_line
  end

  def cmd_go_pro(*args)
    @@go_pro_opts.parse(args) do |opt, idx, val|
      case opt
      when "-h"
        cmd_go_pro_help
        return false
      end
    end
    unless is_apt
      print_warning "This command is only available on deb package installations, such as Kali Linux."
      return false
    end
    unless is_metasploit_debian_package_installed
      print_warning "You need to install the 'metasploit' package first."
      print_warning "Type 'apt-get install -y metasploit' to do this now, then exit"
      print_warning "and restart msfconsole to try again."
      return false
    end
    # If I've gotten this far, I know that this is apt-installed, the
    # metasploit package is here, and I'm ready to rock.
    if is_metasploit_service_running
      launch_metasploit_browser
    else
      print_status "Starting the Metasploit services. This can take a little time."
      start_metasploit_service
      select(nil,nil,nil,3)
      if is_metasploit_service_running
        launch_metasploit_browser
      else
        print_error "Metasploit services aren't running. Type 'service metasploit start' and try again."
      end
    end
    return true
  end

  protected

  #
  # Go_pro methods -- these are used to start and connect to
  # Metasploit Community / Pro.
  #

  # Note that this presumes a default port.
  def launch_metasploit_browser
    cmd = "/usr/bin/xdg-open"

    unless ::File.executable_real? cmd
      print_warning "Can't figure out your default browser, please visit https://localhost:3790"
      print_warning "to start Metasploit Community / Pro."
      return false
    end

    svc_log_pathname = Metasploit::Framework.root.parent.join('engine', 'prosvc_stdout.log')

    unless svc_log_pathname.readable_real?
      print_error "Unable to access log file: #{svc_log_pathname}"
      return false
    end

    really_started = false
    # This method is a little lame but it's a short enough file that it
    # shouldn't really matter that we open and close it a few times.
    timeout = 0
    until really_started
      select(nil,nil,nil,3)

      log_data = svc_log_pathname.open("rb") { |f|
        f.read f.stat.size
      }

      really_started = log_data =~ /Ready/ # This is webserver ready
      if really_started
        print_line
        print_good "Metasploit Community / Pro is up and running, connecting now."
        print_good "If this is your first time connecting, you will be presented with"
        print_good "a self-signed certificate warning. Accept it to create a new user."
        select(nil,nil,nil,7)
        browser_pid = ::Process.spawn(cmd, "https://localhost:3790")
        ::Process.detach(browser_pid)
      elsif timeout >= 200 # 200 * 3 seconds is 10 minutes and that is tons of time.
        print_line
        print_warning "For some reason, Community / Pro didn't start in a timely fashion."
        print_warning "You might want to restart the Metasploit services by typing"
        print_warning "'service metasploit restart'. Sorry it didn't work out."
        return false
      else
        print "."
        timeout += 1
      end
    end
  end

  def start_metasploit_service
    command_pathname = Metasploit::Framework.root.parent.parent.parent.join('scripts', 'start.sh')

    return unless command_pathname.executable_real?

    %x{#{command_pathname}}.each_line do |line|
      print_status line.chomp
    end
  end

  def is_metasploit_service_running
    cmd = "/usr/sbin/service"
    system("#{cmd} metasploit status >/dev/null") # Both running returns true, otherwise, false.
  end

  def is_metasploit_debian_package_installed
    cmd = "/usr/bin/dpkg"
    return unless ::File.executable_real? cmd
    installed_packages = %x{#{cmd} -l 'metasploit'}
    installed_packages.each_line do |line|
      if line =~ /^.i  metasploit / # Yes, trailing space
        return true
      end
    end
    return false
  end

  # Determines if this is an apt-based install
  def is_apt
    Metasploit::Framework.root.join('.apt').exist?
  end

  #
  # Module list enumeration
  #

  def show_encoders(regex = nil, minrank = nil, opts = nil) # :nodoc:
    # If an active module has been selected and it's an exploit, get the
    # list of compatible encoders and display them
    if (metasploit_instance and metasploit_instance.exploit? == true)
      show_module_set("Compatible Encoders", metasploit_instance.compatible_encoders, regex, minrank, opts)
    else
      show_module_set("Encoders", framework.encoders, regex, minrank, opts)
    end
  end

  def show_nops(regex = nil, minrank = nil, opts = nil) # :nodoc:
    show_module_set("NOP Generators", framework.nops, regex, minrank, opts)
  end

  def show_exploits(regex = nil, minrank = nil, opts = nil) # :nodoc:
    show_module_set("Exploits", framework.exploits, regex, minrank, opts)
  end

  def show_payloads(regex = nil, minrank = nil, opts = nil) # :nodoc:
    # If an active module has been selected and it's an exploit, get the
    # list of compatible payloads and display them
    if (metasploit_instance and metasploit_instance.exploit? == true)
      show_module_set("Compatible Payloads", metasploit_instance.compatible_payloads, regex, minrank, opts)
    else
      show_module_set("Payloads", framework.payloads, regex, minrank, opts)
    end
  end

  def show_auxiliary(regex = nil, minrank = nil, opts = nil) # :nodoc:
    show_module_set("Auxiliary", framework.auxiliary, regex, minrank, opts)
  end

  def show_post(regex = nil, minrank = nil, opts = nil) # :nodoc:
    show_module_set("Post", framework.post, regex, minrank, opts)
  end

  def show_global_options
    columns = [ 'Option', 'Current Setting', 'Description' ]
    tbl = Table.new(
      Table::Style::Default,
      'Header'  => 'Global Options:',
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Columns' => columns
      )
    [
      [ 'ConsoleLogging', framework.datastore['ConsoleLogging'] || '', 'Log all console input and output' ],
      [ 'LogLevel', framework.datastore['LogLevel'] || '', 'Verbosity of logs (default 0, max 5)' ],
      [ 'MinimumRank', framework.datastore['MinimumRank'] || '', 'The minimum rank of exploits that will run without explicit confirmation' ],
      [ 'SessionLogging', framework.datastore['SessionLogging'] || '', 'Log all input and output for sessions' ],
      [ 'TimestampOutput', framework.datastore['TimestampOutput'] || '', 'Prefix all console output with a timestamp' ],
      [ 'Prompt', framework.datastore['Prompt'] || '', "The prompt string, defaults to \"#{Msf::Ui::Console::Driver::DEFAULT_PROMPT}\"" ],
      [ 'PromptChar', framework.datastore['PromptChar'] || '', "The prompt character, defaults to \"#{Msf::Ui::Console::Driver::DEFAULT_PROMPT_CHAR}\"" ],
      [ 'PromptTimeFormat', framework.datastore['PromptTimeFormat'] || '', 'A format for timestamp escapes in the prompt, see ruby\'s strftime docs' ],
    ].each { |r| tbl << r }

    print(tbl.to_s)
  end

  def show_targets(mod) # :nodoc:
    mod_targs = Serializer::ReadableText.dump_exploit_targets(mod, '   ')
    print("\nExploit targets:\n\n#{mod_targs}\n") if (mod_targs and mod_targs.length > 0)
  end

  def show_actions(mod) # :nodoc:
    mod_actions = Serializer::ReadableText.dump_auxiliary_actions(mod, '   ')
    print("\nAuxiliary actions:\n\n#{mod_actions}\n") if (mod_actions and mod_actions.length > 0)
  end

  def show_advanced_options(mod) # :nodoc:
    mod_opt = Serializer::ReadableText.dump_advanced_options(mod, '   ')
    print("\nModule advanced options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

    # If it's an exploit and a payload is defined, create it and
    # display the payload's options
    if (mod.exploit? and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])

      if (!p)
        print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
        return
      end

      p.share_datastore(mod.datastore)

      if (p)
        p_opt = Serializer::ReadableText.dump_advanced_options(p, '   ')
        print("\nPayload advanced options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
      end
    end
  end

  def show_evasion_options(mod) # :nodoc:
    mod_opt = Serializer::ReadableText.dump_evasion_options(mod, '   ')
    print("\nModule evasion options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

    # If it's an exploit and a payload is defined, create it and
    # display the payload's options
    if (mod.exploit? and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])

      if (!p)
        print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
        return
      end

      p.share_datastore(mod.datastore)

      if (p)
        p_opt = Serializer::ReadableText.dump_evasion_options(p, '   ')
        print("\nPayload evasion options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
      end
    end
  end

  def show_plugins # :nodoc:
    tbl = Table.new(
      Table::Style::Default,
      'Header'  => 'Plugins',
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Columns' => [ 'Name', 'Description' ]
    )

    framework.plugins.each { |plugin|
      tbl << [ plugin.name, plugin.desc ]
    }

    print(tbl.to_s)
  end

  def show_module_set(type, module_set, regex = nil, minrank = nil, opts = nil) # :nodoc:
    tbl = generate_module_table(type)
    module_set.sort.each { |refname, mod|
      o = nil

      begin
        o = mod.new
      rescue ::Exception
      end
      next if not o

      # handle a search string, search deep
      if(
        not regex or
        o.name.match(regex) or
        o.description.match(regex) or
        o.refname.match(regex) or
        o.references.map{|x| [x.ctx_id + '-' + x.ctx_val, x.to_s]}.join(' ').match(regex) or
        o.author.to_s.match(regex)
      )
        if (not minrank or minrank <= o.rank_number)
          show = true
          if opts
            mod_opt_keys = o.options.keys.map { |x| x.downcase }

            opts.each do |opt,val|
              if mod_opt_keys.include?(opt.downcase) == false or (val != nil and o.datastore[opt] != val)
                show = false
              end
            end
          end
          if (opts == nil or show == true)
            tbl << [ refname, o.disclosure_date||"", o.rank_name, o.name ]
          end
        end
      end
    }

    print(tbl.to_s)
  end

  def generate_module_table(type) # :nodoc:
    Table.new(
      Table::Style::Default,
      'Header'  => type,
      'Prefix'  => "\n",
      'Postfix' => "\n",
      'Columns' => [ 'Name', 'Disclosure Date', 'Rank', 'Description' ]
      )
  end
  #
  # Returns an array of lines at the provided line number plus any before and/or after lines requested
  # from all_lines by supplying the +before+ and/or +after+ parameters which are always positive
  #
  # @param all_lines [Array<String>] An array of all lines being considered for matching
  # @param line_num [Integer] The line number in all_lines which has satisifed the match
  # @param after [Integer] The number of lines after the match line to include (should always be positive)
  # @param before [Integer] The number of lines before the match line to include (should always be positive)
  # @return [Array<String>] Array of lines including the line at line_num and any +before+ and/or +after+

  def retrieve_grep_lines(all_lines,line_num, before = nil, after = nil)
    after = after.to_i.abs
    before = before.to_i.abs
    start = line_num - before
    start = 0 if start < 0
    finish = line_num + after
    return all_lines.slice(start..finish)
  end
end


end end end end
