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
require 'msf/ui/console/command_dispatcher/jobs'
require 'msf/ui/console/command_dispatcher/resource'
require 'msf/ui/console/command_dispatcher/modules'
require 'msf/util/document_generator'

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

  include Msf::Ui::Console::CommandDispatcher

  # Session command options
  @@sessions_opts = Rex::Parser::Arguments.new(
    "-c"  => [ true,  "Run a command on the session given with -i, or all"             ],
    "-C"  => [ true,  "Run a Meterpreter Command on the session given with -i, or all" ],
    "-h"  => [ false, "Help banner"                                                    ],
    "-i"  => [ true,  "Interact with the supplied session ID   "                       ],
    "-l"  => [ false, "List all active sessions"                                       ],
    "-v"  => [ false, "List sessions in verbose mode"                                  ],
    "-q"  => [ false, "Quiet mode"                                                     ],
    "-k"  => [ true,  "Terminate sessions by session ID and/or range"                  ],
    "-K"  => [ false, "Terminate all sessions"                                         ],
    "-s"  => [ true,  "Run a script on the session given with -i, or all"              ],
    "-r"  => [ false, "Reset the ring buffer for the session given with -i, or all"    ],
    "-u"  => [ true,  "Upgrade a shell to a meterpreter session on many platforms"     ],
    "-t"  => [ true,  "Set a response timeout (default: 15)"                           ],
    "-x" =>  [ false, "Show extended information in the session table"                 ])

  @@threads_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ],
    "-k" => [ true,  "Terminate the specified thread ID."             ],
    "-K" => [ false, "Terminate all non-critical threads."            ],
    "-i" => [ true,  "Lists detailed information about a thread."     ],
    "-l" => [ false, "List all background threads."                   ],
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

  @@history_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ],
    "-a" => [ false, "Show all commands in history."                  ],
    "-n" => [ true,  "Show the last n commands."                      ],
    "-u" => [ false, "Show only unique commands."                     ])

  @@irb_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                   ],
    "-e" => [ true,  "Expression to evaluate."                        ])


  # Returns the list of commands supported by this command dispatcher
  def commands
    {
      "?"          => "Help menu",
      "banner"     => "Display an awesome metasploit banner",
      "cd"         => "Change the current working directory",
      "connect"    => "Communicate with a host",
      "color"      => "Toggle color",
      "exit"       => "Exit the console",
      "get"        => "Gets the value of a context-specific variable",
      "getg"       => "Gets the value of a global variable",
      "grep"       => "Grep the output of another command",
      "help"       => "Help menu",
      "history"    => "Show command history",
      "irb"        => "Drop into irb scripting mode",
      "load"       => "Load a framework plugin",
      "quit"       => "Exit the console",
      "route"      => "Route traffic through a session",
      "save"       => "Saves the active datastores",
      "sessions"   => "Dump session listings and display information about sessions",
      "set"        => "Sets a context-specific variable to a value",
      "setg"       => "Sets a global variable to a value",
      "sleep"      => "Do nothing for the specified number of seconds",
      "threads"    => "View and manipulate background threads",
      "unload"     => "Unload a framework plugin",
      "unset"      => "Unsets one or more context-specific variables",
      "unsetg"     => "Unsets one or more global variables",
      "version"    => "Show the framework and console library version numbers",
      "spool"      => "Write console output into a file as well the screen"
    }
  end

  #
  # Initializes the datastore cache
  #
  def initialize(driver)
    super

    @dscache = {}
    @cache_payloads = nil
    @previous_module = nil
    @module_name_stack = []
    @history_limit = 100
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
    banner  = "%cya" + Banner.to_s + "%clr\n\n"

    # These messages should /not/ show up when you're on a git checkout;
    # you're a developer, so you already know all this.
    if (is_apt || binary_install)
      content = [
        "Trouble managing data? List, sort, group, tag and search your pentest data\nin Metasploit Pro -- learn more on http://rapid7.com/metasploit",
        "Frustrated with proxy pivoting? Upgrade to layer-2 VPN pivoting with\nMetasploit Pro -- learn more on http://rapid7.com/metasploit",
        "Payload caught by AV? Fly under the radar with Dynamic Payloads in\nMetasploit Pro -- learn more on http://rapid7.com/metasploit",
        "Easy phishing: Set up email templates, landing pages and listeners\nin Metasploit Pro -- learn more on http://rapid7.com/metasploit",
        "Taking notes in notepad? Have Metasploit Pro track & report\nyour progress and findings -- learn more on http://rapid7.com/metasploit",
        "Tired of typing 'set RHOSTS'? Click & pwn with Metasploit Pro\nLearn more on http://rapid7.com/metasploit",
        "Love leveraging credentials? Check out bruteforcing\nin Metasploit Pro -- learn more on http://rapid7.com/metasploit",
        "Save 45% of your time on large engagements with Metasploit Pro\nLearn more on http://rapid7.com/metasploit",
        "Validate lots of vulnerabilities to demonstrate exposure\nwith Metasploit Pro -- Learn more on http://rapid7.com/metasploit"
      ]
      banner << content.sample # Ruby 1.9-ism!
      banner << "\n\n"
    end

    avdwarn = nil

    banner_trailers = {
      :version     => "%yelmetasploit v#{Metasploit::Framework::VERSION}%clr",
      :exp_aux_pos => "#{framework.stats.num_exploits} exploits - #{framework.stats.num_auxiliary} auxiliary - #{framework.stats.num_post} post",
      :pay_enc_nop => "#{framework.stats.num_payloads} payloads - #{framework.stats.num_encoders} encoders - #{framework.stats.num_nops} nops",
      :free_trial  => "Free Metasploit Pro trial: http://r-7.co/trymsp",
      :padding     => 48
    }

    banner << ("       =[ %-#{banner_trailers[:padding]+8}s]\n" % banner_trailers[:version])
    banner << ("+ -- --=[ %-#{banner_trailers[:padding]}s]\n" % banner_trailers[:exp_aux_pos])
    banner << ("+ -- --=[ %-#{banner_trailers[:padding]}s]\n" % banner_trailers[:pay_enc_nop])

    # TODO: People who are already on a Pro install shouldn't see this.
    # It's hard for Framework to tell the difference though since
    # license details are only in Pro -- we can't see them from here.
    banner << ("+ -- --=[ %-#{banner_trailers[:padding]}s]\n" % banner_trailers[:free_trial])

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

    c2n.join
    n2c.join

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
    elsif(driver.confirm_exit and not forced)
      print("Are you sure you want to exit Metasploit? [y/N]: ")
      response = gets.downcase.chomp
      if(response == "y" || response == "yes")
        driver.stop
      else
        return
      end
    end

    driver.stop
  end

  alias cmd_quit cmd_exit

  def cmd_history(*args)
    length = Readline::HISTORY.length
    uniq   = false

    if length < @history_limit
      limit = length
    else
      limit = @history_limit
    end

    @@history_opts.parse(args) do |opt, idx, val|
      case opt
      when "-a"
        limit = length
      when "-n"
        return cmd_history_help unless val && val.match(/\A[-+]?\d+\z/)
        if length < val.to_i
          limit = length
        else
          limit = val.to_i
        end
      when "-u"
        uniq = true
      when "-h"
        cmd_history_help
        return false
      end
    end

    start   = length - limit
    pad_len = length.to_s.length

    (start..length-1).each do |pos|
      if uniq && Readline::HISTORY[pos] == Readline::HISTORY[pos-1]
        next unless pos == 0
      end
      cmd_num = (pos + 1).to_s
      print_line "#{cmd_num.ljust(pad_len)}  #{Readline::HISTORY[pos]}"
    end
  end

  def cmd_history_help
    print_line "Usage: history [options]"
    print_line
    print_line "Shows the command history."
    print_line "If -n is not set, only the last #{@history_limit} commands will be shown."
    print @@history_opts.usage
  end

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

  def cmd_irb_help
    print_line "Usage: irb"
    print_line
    print_line "Execute commands in a Ruby environment"
    print @@irb_opts.usage
  end

  #
  # Goes into IRB scripting mode
  #
  def cmd_irb(*args)
    expressions = []

    # Parse the command options
    @@irb_opts.parse(args) do |opt, idx, val|
      case opt
      when '-e'
        expressions << val
      when '-h'
        cmd_irb_help
        return false
      end
    end

    if expressions.empty?
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
    else
      expressions.each { |expression| eval(expression, binding) }
    end
  end

  def cmd_threads_help
    print_line "Usage: threads [options]"
    print_line
    print_line "Background thread management."
    print_line @@threads_opts.usage()
  end

  #
  # Displays and manages running background threads
  #
  def cmd_threads(*args)
    # Make the default behavior listing all jobs if there were no options
    # or the only option is the verbose flag
    if (args.length == 0 or args == ["-v"])
      args.unshift("-l")
    end

    verbose = false
    dump_list = false
    dump_info = false
    thread_id = nil

    # Parse the command options
    @@threads_opts.parse(args) { |opt, idx, val|
      case opt
        when "-v"
          verbose = true
        when "-l"
          dump_list = true

        # Terminate the supplied thread id
        when "-k"
          val = val.to_i
          if not framework.threads[val]
            print_error("No such thread")
          else
            print_line("Terminating thread: #{val}...")
            framework.threads.kill(val)
          end
        when "-K"
          print_line("Killing all non-critical threads...")
          framework.threads.each_index do |i|
            t = framework.threads[i]
            next if not t
            next if t[:tm_crit]
            framework.threads.kill(i)
          end
        when "-i"
          # Defer printing anything until the end of option parsing
          # so we can check for the verbose flag.
          dump_info = true
          thread_id = val.to_i
        when "-h"
          cmd_threads_help
          return false
      end
    }

    if (dump_list)
      tbl = Table.new(
        Table::Style::Default,
        'Header'  => "Background Threads",
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' =>
          [
            'ID',
            'Status',
            'Critical',
            'Name',
            'Started'
          ]
      )

      framework.threads.each_index do |i|
        t = framework.threads[i]
        next if not t
        tbl << [ i.to_s, t.status || "dead", t[:tm_crit] ? "True" : "False", t[:tm_name].to_s, t[:tm_time].to_s ]
      end
      print(tbl.to_s)
    end

    if (dump_info)
      thread = framework.threads[thread_id]

      if (thread)
        output  = "\n"
        output += "  ID: #{thread_id}\n"
        output += "Name: #{thread[:tm_name]}\n"
        output += "Info: #{thread.status || "dead"}\n"
        output += "Crit: #{thread[:tm_crit] ? "True" : "False"}\n"
        output += "Time: #{thread[:tm_time].to_s}\n"

        if (verbose)
          output += "\n"
          output += "Thread Source\n"
          output += "=============\n"
          thread[:tm_call].each do |c|
            output += "      #{c.to_s}\n"
          end
          output += "\n"
        end

        print(output + "\n")
      else
        print_line("Invalid Thread ID")
      end
    end
  end

  #
  # Tab completion for the threads command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_threads_tabs(str, words)
    if words.length == 1
      return @@threads_opts.fmt.keys
    end

    if words.length == 2 and (@@threads_opts.fmt[words[1]] || [false])[0]
      return framework.threads.each_index.map{ |idx| idx.to_s }
    end

    []
  end

  def cmd_load_help
    print_line "Usage: load <option> [var=val var=val ...]"
    print_line
    print_line "Loads a plugin from the supplied path."
    print_line "For a list of built-in plugins, do: load -l"
    print_line "The optional var=val options are custom parameters that can be passed to plugins."
    print_line
  end

  def list_plugins
    plugin_directories = {
      'Framework' => Msf::Config.plugin_directory,
      'User'      => Msf::Config.user_plugin_directory
    }

    plugin_directories.each do |type, plugin_directory|
      items = Dir.entries(plugin_directory).keep_if { |n| n.match(/^.+\.rb$/)}
      next if items.empty?
      print_status("Available #{type} plugins:")
      items.each do |item|
        print_line("    * #{item.split('.').first}")
      end
      print_line
    end
  end

  def load_plugin(args)
    path = args[0]

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
      if not File.exist?( path  + ".rb" )
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
      elog("Error loading plugin #{path}: #{e}\n\n#{e.backtrace.join("\n")}", 'core', 0, caller)
      print_error("Failed to load plugin from #{path}: #{e}")
    end
  end

  #
  # Loads a plugin from the supplied path.  If no absolute path is supplied,
  # the framework root plugin directory is used.
  #
  def cmd_load(*args)
    case args[0]
    when '-l'
      list_plugins
    when '-h', nil, ''
      cmd_load_help
    else
      load_plugin(args)
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
    print_line "Route traffic destined to a given subnet through a supplied session."
    print_line
    print_line "Usage:"
    print_line "  route [add/remove] subnet netmask [comm/sid]"
    print_line "  route [add/remove] cidr [comm/sid]"
    print_line "  route [get] <host or network>"
    print_line "  route [flush]"
    print_line "  route [print]"
    print_line
    print_line "Subcommands:"
    print_line "  add - make a new route"
    print_line "  remove - delete a route; 'del' is an alias"
    print_line "  flush - remove all routes"
    print_line "  get - display the route for a given target"
    print_line "  print - show all active routes"
    print_line
    print_line "Examples:"
    print_line "  Add a route for all hosts from 192.168.0.0 to 192.168.0.0 through session 1"
    print_line "    route add 192.168.0.0 255.255.255.0 1"
    print_line "    route add 192.168.0.0/24 1"
    print_line
    print_line "  Delete the above route"
    print_line "    route remove 192.168.0.0/24 1"
    print_line "    route del 192.168.0.0 255.255.255.0 1"
    print_line
    print_line "  Display the route that would be used for the given host or network"
    print_line "    route get 192.168.0.11"
    print_line
  end

  #
  # This method handles the route command which allows a user to specify
  # which session a given subnet should route through.
  #
  def cmd_route(*args)
    args << 'print' if args.length == 0

    action = args.shift
    case action

    when "add", "remove", "del"
      subnet = args.shift
      netmask = nil
      if subnet
        subnet, cidr_mask = subnet.split("/")
        netmask = Rex::Socket.addr_ctoa(cidr_mask.to_i) if cidr_mask
      end

      netmask = args.shift if netmask.nil?
      gateway_name = args.shift

      if (subnet.nil? || netmask.nil? || gateway_name.nil?)
        print_error("Missing arguments to route #{action}.")
        return false
      end

      gateway = nil

      case gateway_name
      when /local/i
        gateway = Rex::Socket::Comm::Local
      when /^(-1|[0-9]+)$/
        session = framework.sessions.get(gateway_name)
        if session.kind_of?(Msf::Session::Comm)
          gateway = session
        elsif session.nil?
          print_error("Not a session: #{gateway_name}")
          return false
        else
          print_error("Cannot route through the specified session (not a Comm)")
          return false
        end
      else
        print_error("Invalid gateway")
        return false
      end

      msg = "Route "
      if action == "remove" or action == "del"
        worked = Rex::Socket::SwitchBoard.remove_route(subnet, netmask, gateway)
        msg << (worked ? "removed" : "not found")
      else
        worked = Rex::Socket::SwitchBoard.add_route(subnet, netmask, gateway)
        msg << (worked ? "added" : "already exists")
      end
      print_status(msg)

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
      # IPv4 Table
      tbl_ipv4 = Table.new(
        Table::Style::Default,
        'Header'  => "IPv4 Active Routing Table",
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

      # IPv6 Table
      tbl_ipv6 = Table.new(
        Table::Style::Default,
        'Header'  => "IPv6 Active Routing Table",
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

      # Populate Route Tables
      Rex::Socket::SwitchBoard.each { |route|
        if (route.comm.kind_of?(Msf::Session))
          gw = "Session #{route.comm.sid}"
        else
          gw = route.comm.name.split(/::/)[-1]
        end

        tbl_ipv4 << [ route.subnet, route.netmask, gw ] if Rex::Socket.is_ipv4?(route.netmask)
        tbl_ipv6 << [ route.subnet, route.netmask, gw ] if Rex::Socket.is_ipv6?(route.netmask)
      }

      # Print Route Tables
      print(tbl_ipv4.to_s) if tbl_ipv4.rows.length > 0
      print(tbl_ipv6.to_s) if tbl_ipv6.rows.length > 0

      if (tbl_ipv4.rows.length + tbl_ipv6.rows.length) < 1
        print_status("There are currently no routes defined.")
      elsif (tbl_ipv4.rows.length < 1) && (tbl_ipv6.rows.length > 0)
        print_status("There are currently no IPv4 routes defined.")
      elsif (tbl_ipv4.rows.length > 0) && (tbl_ipv6.rows.length < 1)
        print_status("There are currently no IPv6 routes defined.")
      end

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
    # Save the console config
    driver.save_config

    # Save the framework's datastore
    begin
      framework.save_config

      if (active_module)
        active_module.save_config
      end
    rescue
      log_error("Save failed: #{$!}")
      return false
    end

    print_line("Saved configuration to: #{Msf::Config.config_file}")
  end


  def cmd_spool_help
    print_line "Usage: spool <off>|<filename>"
    print_line
    print_line "Example:"
    print_line "  spool /tmp/console.log"
    print_line
  end

  def cmd_spool(*args)
    if args.include?('-h') or args.empty?
      cmd_spool_help
      return
    end

    color = driver.output.config[:color]

    if args[0] == "off"
      driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)
      msg = "Spooling is now disabled"
    else
      driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(args[0]))
      msg = "Spooling to file #{args[0]}..."
    end

    # Restore color and prompt
    driver.output.config[:color] = color
    prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
    if active_module
      # intentionally += and not << because we don't want to modify
      # datastore or the constant DefaultPrompt
      prompt += " #{active_module.type}(%bld%red#{active_module.shortname}%clr)"
    end
    prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
    driver.update_prompt("#{prompt} ", prompt_char, true)

    print_status(msg)
    return
  end

  def cmd_sessions_help
    print_line('Usage: sessions [options] or sessions [id]')
    print_line
    print_line('Active session manipulation and interaction.')
    print(@@sessions_opts.usage)
    print_line
    print_line('Many options allow specifying session ranges using commas and dashes.')
    print_line('For example:  sessions -s checkvm -i 1,3-5  or  sessions -k 1-2,5,6')
    print_line
  end

  #
  # Provides an interface to the sessions currently active in the framework.
  #
  def cmd_sessions(*args)
    begin
    method   = nil
    quiet    = false
    show_extended = false
    verbose  = false
    sid      = nil
    cmds     = []
    script   = nil
    reset_ring = false
    response_timeout = 15

    # any arguments that don't correspond to an option or option arg will
    # be put in here
    extra   = []

    if args.length == 1 && args[0] =~ /-?\d+/
      method = 'interact'
      sid = args[0].to_i
    else
      # Parse the command options
      @@sessions_opts.parse(args) do |opt, idx, val|
        case opt
        when '-q'
          quiet = true
        # Run a command on all sessions, or the session given with -i
        when '-c'
          method = 'cmd'
          cmds << val if val
        when '-C'
            method = 'meterp-cmd'
            cmds << val if val
        when '-x'
          show_extended = true
        when '-v'
          verbose = true
        # Do something with the supplied session identifier instead of
        # all sessions.
        when '-i'
          sid = val
        # Display the list of active sessions
        when '-l'
          method = 'list'
        when '-k'
          method = 'kill'
          sid = val || false
        when '-K'
          method = 'killall'
        # Run a script on all meterpreter sessions
        when '-s'
          unless script
            method = 'scriptall'
            script = val
          end
        # Upload and exec to the specific command session
        when '-u'
          method = 'upexec'
          sid = val || false
        # Reset the ring buffer read pointer
        when '-r'
          reset_ring = true
          method = 'reset_ring'
        # Display help banner
        when '-h'
          cmd_sessions_help
          return false
        when '-t'
          if val.to_s =~ /^\d+$/
            response_timeout = val.to_i
          end
        else
          extra << val
        end
      end
    end

    if !method && sid
      method = 'interact'
    end

    unless sid.nil? || method == 'interact'
      session_list = build_range_array(sid)
      if session_list.blank?
        print_error("Please specify valid session identifier(s)")
        return false
      end
    end

    last_known_timeout = nil

    # Now, perform the actual method
    case method
    when 'cmd'
      if cmds.length < 1
        print_error("No command specified!")
        return false
      end
      cmds.each do |cmd|
        if sid
          sessions = session_list
        else
          sessions = framework.sessions.keys.sort
        end
        if sessions.blank?
          print_error("Please specify valid session identifier(s) using -i")
          return false
        end
        sessions.each do |s|
          session = verify_session(s)
          next unless session
          print_status("Running '#{cmd}' on #{session.type} session #{s} (#{session.session_host})")
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end

          begin
            if session.type == 'meterpreter'
              # If session.sys is nil, dont even try..
              unless session.sys
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
                if process && process.channel
                  data = process.channel.read
                  print_line(data) if data
                end
              rescue ::Rex::Post::Meterpreter::RequestError
                print_error("Failed: #{$!.class} #{$!}")
              rescue Rex::TimeoutError
                print_error("Operation timed out")
              end
            elsif session.type == 'shell' || session.type == 'powershell'
              output = session.shell_command(cmd)
              print_line(output) if output
            end
          ensure
            # Restore timeout for each session
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
          # If the session isn't a meterpreter or shell type, it
          # could be a VNC session (which can't run commands) or
          # something custom (which we don't know how to run
          # commands on), so don't bother.
        end
      end
      when 'meterp-cmd'
        if cmds.length < 1
          print_error("No command specified!")
          return false
        end

        if sid
          sessions = session_list
        else
          sessions = framework.sessions.keys.sort
        end
        if sessions.blank?
          print_error("Please specify valid session identifier(s) using -i")
          return false
        end

        cmds.each do |cmd|
          sessions.each do |session|
            session = verify_session(session)
            unless session.type == 'meterpreter'
              print_error "Session ##{session.sid} is not a Meterpreter shell. Skipping..."
              next
            end

            next unless session
            print_status("Running '#{cmd}' on #{session.type} session #{session.sid} (#{session.session_host})")
            if session.respond_to?(:response_timeout)
              last_known_timeout = session.response_timeout
              session.response_timeout = response_timeout
            end

            output = session.run_cmd(cmd, driver.output)
          end
        end
    when 'kill'
      print_status("Killing the following session(s): #{session_list.join(', ')}")
      session_list.each do |sess_id|
        session = framework.sessions.get(sess_id)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          print_status("Killing session #{sess_id}")
          begin
            session.kill
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        else
          print_error("Invalid session identifier: #{sess_id}")
        end
      end
    when 'killall'
      print_status("Killing all sessions...")
      framework.sessions.each_sorted do |s|
        session = framework.sessions.get(s)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          begin
            session.kill
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        end
      end
    when 'interact'
      while sid
        session = verify_session(sid)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          print_status("Starting interaction with #{session.name}...\n") unless quiet
          begin
            self.active_session = session
            sid = session.interact(driver.input.dup, driver.output)
            self.active_session = nil
            driver.input.reset_tab_completion if driver.input.supports_readline
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        else
          sid = nil
        end
      end
    when 'scriptall'
      unless script
        print_error("No script specified!")
        return false
      end
      script_paths = {}
      script_paths['meterpreter'] = Msf::Sessions::Meterpreter.find_script_path(script)
      script_paths['shell'] = Msf::Sessions::CommandShell.find_script_path(script)

      sessions = sid ? session_list : framework.sessions.keys.sort

      sessions.each do |sess_id|
        session = verify_session(sess_id, true)
        # @TODO: Not interactive sessions can or cannot have scripts run on them?
        if session == false # specifically looking for false
          # if verify_session returned false, sess_id is valid, but not interactive
          session = framework.sessions.get(sess_id)
        end
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          begin
            if script_paths[session.type]
              print_status("Session #{sess_id} (#{session.session_host}):")
              print_status("Running script #{script} on #{session.type} session" +
                            " #{sess_id} (#{session.session_host})")
              begin
                session.execute_file(script_paths[session.type], extra)
              rescue ::Exception => e
                log_error("Error executing script: #{e.class} #{e}")
              end
            end
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        else
          print_error("Invalid session identifier: #{sess_id}")
        end
      end
    when 'upexec'
      print_status("Executing 'post/multi/manage/shell_to_meterpreter' on " +
                    "session(s): #{session_list}")
      session_list.each do |sess_id|
        session = verify_session(sess_id)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          begin
            if ['shell', 'powershell'].include?(session.type)
              session.init_ui(driver.input, driver.output)
              session.execute_script('post/multi/manage/shell_to_meterpreter')
              session.reset_ui
            else
              print_error("Session #{sess_id} is not a command shell session, it is #{session.type}, skipping...")
              next
            end
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        end

        if session_list.count > 1
          print_status("Sleeping 5 seconds to allow the previous handler to finish..")
          sleep(5)
        end
      end
    when 'reset_ring'
      sessions = sid ? [sid] : framework.sessions.keys
      sessions.each do |sidx|
        s = framework.sessions[sidx]
        next unless (s && s.respond_to?(:ring_seq))
        s.reset_ring_sequence
        print_status("Reset the ring buffer pointer for Session #{sidx}")
      end
    when 'list',nil
      print_line
      print(Serializer::ReadableText.dump_sessions(framework, :show_extended => show_extended, :verbose => verbose))
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

    true
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
    when "-i", "-k", "-u"
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
    if (active_module and global == false)
      datastore = active_module.datastore
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
          (global) ? "Global" : "Module: #{active_module.refname}",
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

    # Warn when setting RHOST option for module which expects RHOSTS
    if args.first.upcase.eql?('RHOST')
      mod = active_module
      unless mod.nil?
        if !mod.options.include?('RHOST') && mod.options.include?('RHOSTS')
          warn_rhost = false
          if mod.exploit? && mod.datastore['PAYLOAD']
            p = framework.payloads.create(mod.datastore['PAYLOAD'])
            warn_rhost = (p && !p.options.include?('RHOST'))
          else
            warn_rhost = true
          end
          print_warning("RHOST is not a valid option for this module. Did you mean RHOSTS?") if warn_rhost
        end
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

    # If the driver indicates that the value is not valid, bust out.
    if (driver.on_variable_set(global, name, value) == false)
      print_error("The value specified for #{name} is not valid.")
      return true
    end

    begin
      if append
        datastore[name] = datastore[name] + value
      else
        datastore[name] = value
      end
    rescue OptionValidateError => e
      print_error(e.message)
      elog(e.message)
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
    mod = active_module

    if (not mod)
      return res
    end

    mod.options.sorted.each { |e|
      name, _opt = e
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

    if mod.kind_of?(Msf::Module::HasActions)
      res << "ACTION"
    end

    if (mod.exploit? and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])
      if (p)
        p.options.sorted.each { |e|
          name, _opt = e
          res << name
        }
      end
    end

    unless str.blank?
      res = res.select { |term| term.upcase.start_with?(str.upcase) }
      res = res.map { |term|
        if str == str.upcase
          str + term[str.length..-1].upcase
        elsif str == str.downcase
          str + term[str.length..-1].downcase
        else
          str + term[str.length..-1]
        end
      }
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

    # Find a plugin within the plugins array
    plugin = framework.plugins.find { |p| p.name.downcase == args[0].downcase }

    # Unload the plugin if it matches the name we're searching for
    if plugin
      print("Unloading plugin #{args[0]}...")
      framework.plugins.unload(plugin)
      print_line("unloaded.")
    end
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

  def cmd_get_help
    print_line "Usage: get var1 [var2 ...]"
    print_line
    print_line "The get command is used to get the value of one or more variables."
    print_line
  end

  #
  # Gets a value if it's been set.
  #
  def cmd_get(*args)

    # Figure out if these are global variables
    global = false

    if (args[0] == '-g')
      args.shift
      global = true
    end

    # No arguments?  No cookie.
    if args.empty?
      global ? cmd_getg_help : cmd_get_help
      return false
    end

    # Determine which data store we're operating on
    if (active_module && !global)
      datastore = active_module.datastore
    else
      datastore = framework.datastore
    end

    args.each { |var| print_line("#{var} => #{datastore[var]}") }
  end

  #
  # Tab completion for the get command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_get_tabs(str, words)
    datastore = active_module ? active_module.datastore : self.framework.datastore
    datastore.keys
  end

  def cmd_getg_help
    print_line "Usage: getg var1 [var2 ...]"
    print_line
    print_line "Exactly like get -g, get global variables"
    print_line
  end

  #
  # Gets variables in the global data store.
  #
  def cmd_getg(*args)
    args.unshift('-g')

    cmd_get(*args)
  end

  #
  # Tab completion for the getg command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed

  def cmd_getg_tabs(str, words)
    self.framework.datastore.keys
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
    if (active_module and global == false)
      datastore = active_module.datastore
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
      if (active_module and global == false)
        active_module.import_defaults
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
  # @param words [Array<String>] the previously completed words on the command
  #   line. `words` is always at least 1 when tab completion has reached this
  #   stage since the command itself has been completed.
  def cmd_unset_tabs(str, words)
    datastore = active_module ? active_module.datastore : self.framework.datastore
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
  # Returns the revision of the framework and console library
  #
  def cmd_version(*args)
    print_line("Framework: #{Msf::Framework::Version}")
    print_line("Console  : #{Msf::Framework::Version}")
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
    prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
    prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
    mod = active_module
    if mod # if there is an active module, give them the fanciness they have come to expect
      driver.update_prompt("#{prompt} #{mod.type}(%bld%red#{mod.shortname}%clr) ", prompt_char, true)
    else
      driver.update_prompt("#{prompt} ", prompt_char, true)
    end

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
  # Provide tab completion for option values
  #
  def tab_complete_option(str, words)
    opt = words[1]
    res = []
    mod = active_module

    # With no active module, we have nothing to compare
    if (not mod)
      return res
    end

    # Well-known option names specific to exploits
    if (mod.exploit?)
      return option_values_payloads() if opt.upcase == 'PAYLOAD'
      return option_values_targets()  if opt.upcase == 'TARGET'
      return option_values_nops()     if opt.upcase == 'NOPS'
      return option_values_encoders() if opt.upcase == 'STAGEENCODER'
    end

    # Well-known option names specific to modules with actions
    if mod.kind_of?(Msf::Module::HasActions)
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
    elsif (mod.options.include?(opt.upcase))
      res.concat(option_values_dispatch(mod.options[opt.upcase], str, words))
    end

    # How about the selected payload?
    if (mod.exploit? and mod.datastore['PAYLOAD'])
      p = framework.payloads.create(mod.datastore['PAYLOAD'])
      if (p and p.options.include?(opt))
        res.concat(option_values_dispatch(p.options[opt], str, words))
      elsif (p and p.options.include?(opt.upcase))
        res.concat(option_values_dispatch(p.options[opt.upcase], str, words))
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

    case o
    when Msf::OptAddress
      case o.name.upcase
      when 'RHOST'
        option_values_target_addrs().each do |addr|
          res << addr
        end
      when 'LHOST', 'SRVHOST', 'REVERSELISTENERBINDADDRESS'
        rh = self.active_module.datastore['RHOST'] || framework.datastore['RHOST']
        if rh and not rh.empty?
          res << Rex::Socket.source_address(rh)
        else
          res << Rex::Socket.source_address
          # getifaddrs was introduced in 2.1.2
          if Socket.respond_to?(:getifaddrs)
            ifaddrs = Socket.getifaddrs.find_all do |ifaddr|
              ((ifaddr.flags & Socket::IFF_LOOPBACK) == 0) &&
                ifaddr.addr &&
                ifaddr.addr.ip?
            end
            res += ifaddrs.map { |ifaddr| ifaddr.addr.ip_address }
          end
        end
      else
      end

    when Msf::OptAddressRange
      case str
      when /^file:(.*)/
        files = tab_complete_filenames($1, words)
        res += files.map { |f| "file:" + f } if files
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

    when Msf::OptPort
      case o.name.upcase
      when 'RPORT'
        option_values_target_ports().each do |port|
          res << port
        end
      end

      if (res.empty?)
        res << (rand(65534)+1).to_s
      end

    when Msf::OptEnum
      o.enums.each do |val|
        res << val
      end

    when Msf::OptPath
      files = tab_complete_filenames(str, words)
      res += files if files

    when Msf::OptBool
      res << 'true'
      res << 'false'

    when Msf::OptString
      if (str =~ /^file:(.*)/)
        files = tab_complete_filenames($1, words)
        res += files.map { |f| "file:" + f } if files
      end
    end

    return res
  end

  #
  # Provide valid payload options for the current exploit
  #
  def option_values_payloads
    return @cache_payloads if @cache_payloads

    @cache_payloads = active_module.compatible_payloads.map { |refname, payload|
      refname
    }

    @cache_payloads
  end

  #
  # Provide valid session options for the current post-exploit module
  #
  def option_values_sessions
    active_module.compatible_sessions.map { |sid| sid.to_s }
  end

  #
  # Provide valid target options for the current exploit
  #
  def option_values_targets
    res = []
    if (active_module.targets)
      1.upto(active_module.targets.length) { |i| res << (i-1).to_s }
    end
    return res
  end


  #
  # Provide valid action options for the current module
  #
  def option_values_actions
    res = []
    if (active_module.actions)
      active_module.actions.each { |i| res << i.name }
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
    return res if not framework.db.active

    # List only those hosts with matching open ports?
    mport = self.active_module.datastore['RPORT']
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

    return res
  end

  #
  # Provide the target ports
  #
  def option_values_target_ports
    res = [ ]
    return res if not framework.db.active
    return res if not self.active_module.datastore['RHOST']
    host = framework.db.has_host?(framework.db.workspace, self.active_module.datastore['RHOST'])
    return res if not host

    framework.db.each_service(framework.db.workspace) do |service|
      if (service.host_id == host.id)
        res << service.port.to_s
      end
    end

    return res
  end

  protected

  #
  # verifies that a given session_id is valid and that the session is interactive.
  # The various return values allow the caller to make better decisions on what
  # action can & should be taken depending on the capabilities of the session
  # and the caller's objective while making it simple to use in the nominal case
  # where the caller needs session_id to match an interactive session
  #
  # @param session_id [String] A session id, which is an integer as a string
  # @param quiet [Boolean] True means the method will produce no error messages
  # @return [session] if the given session_id is valid and session is interactive
  # @return [false] if the given session_id is valid, but not interactive
  # @return [nil] if the given session_id is not valid at all
  def verify_session(session_id, quiet = false)
    session = framework.sessions.get(session_id)
    if session
      if session.interactive?
        session
      else
        print_error("Session #{session_id} is non-interactive.") unless quiet
        false
      end
    else
      print_error("Invalid session identifier: #{session_id}") unless quiet
      nil
    end
  end

  # Determines if this is an apt-based install
  def is_apt
    File.exist?(File.expand_path(File.join(Msf::Config.install_root, '.apt')))
  end

  # Determines if we're a Metasploit Pro/Community/Express
  # installation or a tarball/git checkout
  #
  # XXX This will need to be update when we embed framework as a gem in
  # commercial packages
  #
  # @return [Boolean] true if we are a binary install
  def binary_install
    binary_paths = [
      'C:/metasploit/apps/pro/msf3',
      '/opt/metasploit/apps/pro/msf3'
    ]
    return binary_paths.include? Msf::Config.install_root
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
    all_lines.slice(start..finish)
  end



end

end end end end
