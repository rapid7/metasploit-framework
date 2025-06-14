# -*- coding: binary -*-

#
# Rex
#


#
# Project
#


require 'msf/core/opt_condition'
require 'optparse'

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
  include Msf::Ui::Console::CommandDispatcher::Common
  include Msf::Ui::Console::ModuleOptionTabCompletion

  # Session command options
  @@sessions_opts = Rex::Parser::Arguments.new(
    ["-c", "--command"]              => [ true,  "Run a command on the session given with -i, or all", "<command>"               ],
    ["-C", "--meterpreter-command"]  => [ true,  "Run a Meterpreter Command on the session given with -i, or all", "<command>"   ],
    ["-h", "--help"]                 => [ false, "Help banner"                                                                   ],
    ["-i", "--interact"]             => [ true,  "Interact with the supplied session ID", "<id>"                                 ],
    ["-l", "--list"]                 => [ false, "List all active sessions"                                                      ],
    ["-v", "--list-verbose"]         => [ false, "List all active sessions in verbose mode"                                      ],
    ["-d", "--list-inactive"]        => [ false, "List all inactive sessions"                                                    ],
    ["-q", "--quiet"]                => [ false, "Quiet mode"                                                                    ],
    ["-k", "--kill"]                 => [ true,  "Terminate sessions by session ID and/or range", "<id>"                         ],
    ["-K", "--kill-all"]             => [ false, "Terminate all sessions"                                                        ],
    ["-s", "--script"]               => [ true,  "Run a script or module on the session given with -i, or all", "<script>"       ],
    ["-u", "--upgrade"]              => [ true,  "Upgrade a shell to a meterpreter session on many platforms", "<id>"            ],
    ["-t", "--timeout"]              => [ true,  "Set a response timeout (default: 15)", "<seconds>"                             ],
    ["-S", "--search"]               => [ true,  "Row search filter. (ex: sessions --search 'last_checkin:less_than:10s session_id:5 session_type:meterpreter')", "<filter>"],
    ["-x", "--list-extended"]        => [ false, "Show extended information in the session table"                                ],
    ["-n", "--name"]                 => [ true,  "Name or rename a session by ID", "<id> <name>"                                 ])


  @@threads_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"]            => [ false, "Help banner."                                           ],
    ["-k", "--kill"]            => [ true,  "Terminate the specified thread ID.", "<id>"             ],
    ["-K", "--kill-all"]        => [ false, "Terminate all non-critical threads."                    ],
    ["-i", "--info"]            => [ true,  "Lists detailed information about a thread.", "<id>"     ],
    ["-l", "--list"]            => [ false, "List all background threads."                           ],
    ["-v", "--verbose"]         => [ false, "Print more detailed info.  Use with -i and -l"          ])

  @@tip_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"] => [ false, "Help banner."                                   ])

  @@debug_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"]            => [ false, "Help banner."                                   ],
    ["-d", "--datastore"]       => [ false, "Display the datastore information."             ],
    ["-c", "--commands"] => [ false, "Display command history."                       ],
    ["-e", "--errors"]     => [ false, "Display the most recent Error and Stack Trace." ],
    ["-l", "--logs"]            => [ false, "Display the most recent logs."                  ],
    ["-v", "--version"]         => [ false, "Display versions and install info."             ],
    ["-s", "--database"]           => [ false, "Display database statistics."                   ])

  @@connect_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"]           => [ false, "Help banner."                                                ],
    ["-p", "--proxies"]        => [ true,  "List of proxies to use.", "<proxies>"                        ],
    ["-C", "--crlf"]           => [ false, "Try to use CRLF for EOL sequence."                           ],
    ["-c", "--comm"]           => [ true,  "Specify which Comm to use.", "<comm>"                        ],
    ["-i", "--send-contents"]  => [ true,  "Send the contents of a file.", "<file>"                      ],
    ["-P", "--source-port"]    => [ true,  "Specify source port.", "<port>"                              ],
    ["-S", "--source-address"] => [ true,  "Specify source address.", "<address>"                        ],
    ["-s", "--ssl"]            => [ false, "Connect with SSL."                                           ],
    ["-u", "--udp"]            => [ false, "Switch to a UDP socket."                                     ],
    ["-w", "--timeout"]        => [ true,  "Specify connect timeout.", "<seconds>"                       ],
    ["-z", "--try-connection"] => [ false, "Just try to connect, then return."                           ])

  @@history_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"]            => [ false, "Help banner."                                   ],
    ["-a", "--all-commands"]    => [ false, "Show all commands in history."                  ],
    ["-n"] => [ true,  "Show the last n commands.", "<num>"             ],
    ["-c", "--clear"]           => [ false, "Clear command history and history file."        ])

  @@save_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"]           => [ false, "Help banner."                                                                   ],
    ["-r", "--reload-default"] => [ false, "Reload default options for the active module."                                  ],
    ["-l", "--load"]           => [ false, "Load the saved options for the active module."                                  ],
    ["-d", "--delete-all"]     => [ false, "Delete saved options for all modules from the config file."                     ])

  # set command options
  @@setg_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"] => [ false, "Help banner."],
    ["-c", "--clear"] => [ false, "Clear the values, explicitly setting to nil (default)"]
  )

  @@set_opts = @@setg_opts.merge(
    ["-g", "--global"] => [ false, "Operate on global datastore variables"]
  )

  # unset command options
  @@unsetg_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"] => [ false, "Help banner."],
  )

  @@unset_opts = @@unsetg_opts.merge(
    ["-g", "--global"] => [ false, "Operate on global datastore variables"]
  )

  SESSION_TYPE = 'session_type'
  SESSION_ID = 'session_id'
  LAST_CHECKIN = 'last_checkin'
  LESS_THAN = 'less_than'
  GREATER_THAN = 'greater_than'

  VALID_SESSION_SEARCH_PARAMS =
    [
      LAST_CHECKIN,
      SESSION_ID,
      SESSION_TYPE
    ]
  VALID_OPERATORS =
    [
      LESS_THAN,
      GREATER_THAN
    ]

  private_constant :VALID_SESSION_SEARCH_PARAMS
  private_constant :VALID_OPERATORS
  private_constant :SESSION_TYPE
  private_constant :SESSION_ID
  private_constant :LAST_CHECKIN
  private_constant :GREATER_THAN
  private_constant :LESS_THAN

  # Returns the list of commands supported by this command dispatcher
  def commands
    {
      "?"          => "Help menu",
      "banner"     => "Display an awesome metasploit banner",
      "cd"         => "Change the current working directory",
      "connect"    => "Communicate with a host",
      "color"      => "Toggle color",
      "debug"      => "Display information useful for debugging",
      "exit"       => "Exit the console",
      "features"   => "Display the list of not yet released features that can be opted in to",
      "get"        => "Gets the value of a context-specific variable",
      "getg"       => "Gets the value of a global variable",
      "grep"       => "Grep the output of another command",
      "help"       => "Help menu",
      "history"    => "Show command history",
      "load"       => "Load a framework plugin",
      "quit"       => "Exit the console",
      "repeat"     => "Repeat a list of commands",
      "route"      => "Route traffic through a session",
      "save"       => "Saves the active datastores",
      "sessions"   => "Dump session listings and display information about sessions",
      "set"        => "Sets a context-specific variable to a value",
      "setg"       => "Sets a global variable to a value",
      "sleep"      => "Do nothing for the specified number of seconds",
      "tips"       => "Show a list of useful productivity tips",
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

    @cache_payloads = nil
    @previous_module = nil
    @previous_target = nil
    @history_limit = 100
  end

  def deprecated_commands
    ['tip']
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
  end

  #
  # Tab completion for the color command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  #
  def cmd_color_tabs(str, words)
    return [] if words.length > 1
    %w[auto true false]
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

  def cmd_cd_tabs(str, words)
    tab_complete_directory(str, words)
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

    stats       = framework.stats
    version     = "%yelmetasploit v#{Metasploit::Framework::VERSION}%clr",
    exp_aux_pos = "#{stats.num_exploits} exploits - #{stats.num_auxiliary} auxiliary - #{stats.num_post} post",
    pay_enc_nop = "#{stats.num_payloads} payloads - #{stats.num_encoders} encoders - #{stats.num_nops} nops",
    eva         = "#{stats.num_evasion} evasion",
    padding     = 48

    banner << ("       =[ %-#{padding+8}s]\n" % version)
    banner << ("+ -- --=[ %-#{padding}s]\n" % exp_aux_pos)
    banner << ("+ -- --=[ %-#{padding}s]\n" % pay_enc_nop)
    banner << ("+ -- --=[ %-#{padding}s]\n" % eva)

    banner << "\n"
    banner << Rex::Text.wordwrap('Metasploit Documentation: https://docs.metasploit.com/', indent = 0, cols = 60)

    # Display the banner
    print_line(banner)

  end

  #
  # Tab completion for the tips command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_tips_tabs(str, words)
    if words.length == 1
      return @@tip_opts.option_keys.select { |opt| opt.start_with?(str) }
    end

    []
  end

  def cmd_tips_help
    print_line "Usage: tips [options]"
    print_line
    print_line "Print a useful list of productivity tips on how to use Metasploit"
    print @@tip_opts.usage
  end

  alias cmd_tip_help cmd_tips_help

  #
  # Display useful productivity tips to the user.
  #
  def cmd_tips(*args)
    if args.include?("-h") || args.include?("--help")
      cmd_tip_help
    else
      tbl = Table.new(
        Table::Style::Default,
        'Columns' => %w[Id Tip]
      )

      Tip.all.each_with_index do |tip, index|
        tbl << [ index, tip ]
      end

      print(tbl.to_s)
    end
  end

  alias cmd_tip cmd_tips

  #
  # Tab completion for the debug command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_debug_tabs(str, words)
    if words.length >= 1
      return @@debug_opts.option_keys.select do |opt|
        opt.start_with?(str) && !words.include?(opt)
      end
    end

    []
  end

  def cmd_debug_help
    print_line "Usage: debug [options]"
    print_line
    print_line("Print a set of information in a Markdown format to be included when opening an Issue on Github. " +
                 "This information helps us fix problems you encounter and should be included when you open a new issue: " +
                 Debug.issue_link)
    print @@debug_opts.usage
  end

  #
  # Display information useful for debugging errors.
  #
  def cmd_debug(*args)
    if args.empty?
      print_line Debug.all(framework, driver)
      return
    end

    if args.include?("-h") || args.include?("--help")
      cmd_debug_help
    else
      output = ""
      @@debug_opts.parse(args) do |opt|
        case opt
        when '-d'
          output << Debug.datastore(framework, driver)
        when '-c'
          output << Debug.history(driver)
        when '-e'
          output << Debug.errors
        when '-l'
          output << Debug.logs
        when '-v'
          output << Debug.versions(framework)
        when '-s'
          output << Debug.database_configuration(framework)
        end
      end

      if output.empty?
        print_line("Valid argument was not given.")
        cmd_debug_help
      else
        output = Debug.preamble + output
        print_line output
      end
    end
  end

  #
  # Tab completion for the connect command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_connect_tabs(str, words)
    if words.length == 1
      return @@connect_opts.option_keys.select do |opt|
        opt.start_with?(str) && !words.include?(opt)
      end
    end

    case words[-1]
    when '-c', '--comm'
      # Rex::Socket::Comm
    end

    []
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
    if args.length < 2 or args.include?("-h") or args.include?("--help")
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

    _, lhost, lport = sock.getlocalname()
    print_status("Connected to #{host}:#{port} (via: #{lhost}:#{lport})")

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

  def cmd_features_help
    print_line <<~CMD_FEATURE_HELP
      Enable or disable unreleased features that Metasploit supports

      Usage:
        features set feature_name [true/false]
        features print

      Subcommands:
        set - Enable or disable a given feature
        print - show all available features and their current configuration

      Examples:
        View available features:
          features print

        Enable a feature:
          features set new_feature true

        Disable a feature:
          features set new_feature false
    CMD_FEATURE_HELP
  end

  #
  # This method handles the features command which allows a user to opt into enabling
  # features that are not yet released to everyone by default.
  #
  def cmd_features(*args)
    args << 'print' if args.empty?

    action, *rest = args
    case action
    when 'set'
      feature_name, value = rest

      unless framework.features.exists?(feature_name)
        print_warning("Feature name '#{feature_name}' is not available. Either it has been removed, integrated by default, or does not exist in this version of Metasploit.")
        print_warning("Currently supported features: #{framework.features.names.join(', ')}") if framework.features.all.any?
        print_warning('There are currently no features to toggle.') if framework.features.all.empty?
        return
      end

      unless %w[true false].include?(value)
        print_warning('Please specify true or false to configure this feature.')
        return
      end

      framework.features.set(feature_name, value == 'true')
      print_line("#{feature_name} => #{value}")
      # Some flags may require a full console restart
      if framework.features.requires_restart?(feature_name)
        print_warning("Run the #{Msf::Ui::Tip.highlight("save")} command and restart the console for this feature to take effect.")
      else
        # Reload the current module, as feature flags may impact the available module options etc
        driver.run_single("reload") if driver.active_module
      end
    when 'print'
      if framework.features.all.empty?
        print_line 'There are no features to enable at this time. Either the features have been removed, or integrated by default.'
        return
      end

      features_table = Table.new(
        Table::Style::Default,
        'Header' => 'Features table',
        'Prefix' => "\n",
        'Postfix' => "\n",
        'Columns' => [
          '#',
          'Name',
          'Enabled',
          'Description',
        ]
      )

      framework.features.all.each.with_index do |feature, index|
        features_table << [
          index,
          feature[:name],
          feature[:enabled].to_s,
          feature[:description]
        ]
      end

      print_line features_table.to_s
    else
      cmd_features_help
    end
  rescue StandardError => e
    elog(e)
    print_error(e.message)
  end

  #
  # Tab completion for the features command
  #
  # @param _str [String] The string currently being typed before tab was hit
  # @param words [Array<String>] The previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_features_tabs(_str, words)
    if words.length == 1
      return %w[set print]
    end

    _command_name, action, *rest = words
    ret = []
    case action
    when 'set'
      feature_name, _value = rest

      if framework.features.exists?(feature_name)
        ret += %w[true false]
      else
        ret += framework.features.names
      end
    end

    ret
  end

  def cmd_history(*args)
    length = Readline::HISTORY.length

    if length < @history_limit
      limit = length
    else
      limit = @history_limit
    end

    @@history_opts.parse(args) do |opt, idx, val|
      case opt
      when '-a'
        limit = length
      when '-n'
        return cmd_history_help unless val && val.match(/\A[-+]?\d+\z/)
        if length < val.to_i
          limit = length
        else
          limit = val.to_i
        end
      when '-c'
        if Readline::HISTORY.respond_to?(:clear)
          Readline::HISTORY.clear
        elsif defined?(RbReadline)
          RbReadline.clear_history
        else
          print_error('Could not clear history, skipping file')
          return false
        end

        # Portable file truncation?
        if File.writable?(Msf::Config.history_file)
          File.write(Msf::Config.history_file, '')
        end

        print_good('Command history and history file cleared')

        return true
      when '-h'
        cmd_history_help
        return false
      end
    end

    start   = length - limit
    pad_len = length.to_s.length

    (start..length-1).each do |pos|
      cmd_num = (pos + 1).to_s
      print_line "#{cmd_num.ljust(pad_len)}  #{Readline::HISTORY[pos]}"
    end
  end

  def cmd_history_help
    print_line "Usage: history [options]"
    print_line
    print_line "Shows the command history."
    print_line
    print_line "If -n is not set, only the last #{@history_limit} commands will be shown."
    print_line 'If -c is specified, the command history and history file will be cleared.'
    print_line 'Start commands with a space to avoid saving them to history.'
    print @@history_opts.usage
  end

  def cmd_history_tabs(str, words)
    return [] if words.length > 1
    @@history_opts.option_keys
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
      return @@threads_opts.option_keys
    end

    if words.length == 2 && @@threads_opts.include?(words[1]) && @@threads_opts.arg_required?(words[1])
      return framework.threads.each_index.map{ |idx| idx.to_s }
    end

    []
  end

  def cmd_load_help
    print_line "Usage: load <option> [var=val var=val ...]"
    print_line
    print_line "Loads a plugin from the supplied path."
    print_line "For a list of built-in plugins, do: load -l"
    print_line "For a list of loaded plugins, do: load -s"
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
      items.sort.each do |item|
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
      k, v = opt.split('=')

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
      elog("Error loading plugin #{path}", error: e)
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
    when '-s'
      framework.plugins.each{ |p| print_line p.name }
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

    return tabs.map{|e| e.sub('.rb', '')} - framework.plugins.map(&:name)
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
    print_line "  Add a route for all hosts from 192.168.0.0 to 192.168.0.255 through session 1"
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
    begin
      args << 'print' if args.length == 0

      action = args.shift
      case action
      when "add", "remove", "del"
        subnet = args.shift
        subnet, cidr_mask = subnet.split("/")

        if Rex::Socket.is_ip_addr?(args.first)
          netmask = args.shift
        elsif Rex::Socket.is_ip_addr?(subnet)
          cidr_mask ||= Rex::Socket.is_ipv6?(subnet) ? 128 : 32
          netmask = Rex::Socket.addr_ctoa(cidr_mask, v6: Rex::Socket.is_ipv6?(subnet))
        end

        netmask = args.shift if netmask.nil?
        gateway_name = args.shift

        if (subnet.nil? || netmask.nil? || gateway_name.nil?)
          print_error("Missing arguments to route #{action}.")
          return false
        end

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
              'Subnet'  => { 'Width' => 17 },
              'Netmask' => { 'Width' => 17 },
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
              'Subnet'  => { 'Width' => 17 },
              'Netmask' => { 'Width' => 17 },
            })

        # Populate Route Tables
        Rex::Socket::SwitchBoard.each { |route|
          if (route.comm.kind_of?(Msf::Session))
            gw = "Session #{route.comm.sid}"
          else
            gw = route.comm.name.split('::')[-1]
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
    rescue => error
      elog(error)
      print_error(error.message)
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

  #
  # Tab completion for the save command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_save_tabs(str, words)
    if words.length == 1
      @@save_opts.option_keys.select { |opt| opt.start_with?(str) }
    end
  end

  # Print save help information
  def cmd_save_help
    print_line 'Usage: save [options]'
    print_line
    print_line 'Save the active datastore contents to disk for automatic use across restarts of the console'
    print_line "The configuration is stored in #{Msf::Config.config_file}"
    print @@save_opts.usage
  end

  #
  # Deletes or saves the active datastore contents to disk for automatic use across
  # restarts of the console.
  #
  def cmd_save(*args)
    if args.include?('-h') || args.include?('--help')
      cmd_save_help
      return false
    end

    if args.empty?
      # Save config for current module
      # Save the console config
      driver.save_config

      begin
        FeatureManager.instance.save_config
      rescue StandardException => e
        elog(e)
      end

      # Save the framework's datastore
      begin
        framework.save_config
        if driver.framework.dns_resolver
          driver.framework.dns_resolver.save_config
        end

        if active_module
          active_module.save_config
        end
      rescue
        log_error("Save failed: #{$!}")
        return false
      end

      print_line("Saved configuration to: #{Msf::Config.config_file}")
    end

    @@save_opts.parse(args) do |opt|
      case opt
      when '-d'
        # Delete all saved options for modules from the config file.
        # No framework options will be deleted.
        begin
          ini = Rex::Parser::Ini.new(::Msf::Config.config_file)

          ini.delete_if { |k, _v| !k.start_with?('framework') }

          ini.to_file(::Msf::Config.config_file)
        rescue StandardError
          print_error("Failed to delete console config: #{$!}")
        end

        if active_module
          active_module.import_defaults
        end
        print_line('Deleted saved configs for all modules.')
      when '-r'
        active_module.import_defaults
        print_line('Reloaded default options.')
      when '-l'
        active_module.load_config
        print_line("Loaded config from #{Msf::Config.config_file}.")
      when '-h'
        cmd_save_help
        return false
      else
        print_line("Unknown option: #{opt}")
        print(@@save_opts.usage)
      end
    end
  end

  def cmd_spool_help
    print_line "Usage: spool <off>|<filename>"
    print_line
    print_line "Example:"
    print_line "  spool /tmp/console.log"
    print_line
  end

  def cmd_spool_tabs(str, words)
    tab_complete_filenames(str, words)
  end

  def cmd_spool(*args)
    if args.include?('-h') or args.empty?
      cmd_spool_help
      return
    end

    color = driver.output.config[:color]

    if args[0] == "off"
      stdout = Rex::Ui::Text::Output::Stdio.new
      driver.init_ui(driver.input, stdout)
      active_module.init_ui(driver.input, stdout) if defined?(active_module) && active_module
      msg = "Spooling is now disabled"
    else
      stdout = Rex::Ui::Text::Output::Tee.new(args[0])
      driver.init_ui(driver.input, stdout)
      active_module.init_ui(driver.input, stdout) if defined?(active_module) && active_module
      msg = "Spooling to file #{args[0]}..."
    end

    # Restore color
    driver.output.config[:color] = color

    print_status(msg)
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
    show_active = false
    show_inactive = false
    show_extended = false
    verbose  = false
    sid      = nil
    cmds     = []
    script   = nil
    response_timeout = 15
    search_term = nil
    session_name = nil
    has_script_arguments = false

    # any arguments that don't correspond to an option or option arg will
    # be put in here
    extra   = []

    if args.length == 1 && args[0] =~ /-?\d+/
      method = 'interact'
      sid = args[0].to_i
    else
      # Parse the command options
      @@sessions_opts.parse(args) do |opt, idx, val|
        next if has_script_arguments

        case opt
        when "-q", "--quiet"
          quiet = true
        # Run a command on all sessions, or the session given with -i
        when "-c", "--command"
          method = 'cmd'
          cmds << val if val
        when "-C", "--meterpreter-command"
            method = 'meterp-cmd'
            cmds << val if val
        # Display the list of inactive sessions
        when "-d", "--list-inactive"
          show_inactive = true
          method = 'list_inactive'
        when "-x", "--list-extended"
          show_extended = true
        when "-v", "--list-verbose"
          verbose = true
        # Do something with the supplied session identifier instead of
        # all sessions.
        when "-i", "--interact"
          sid = val
        # Display the list of active sessions
        when "-l", "--list"
          show_active = true
          method = 'list'
        when "-k", "--kill"
          method = 'kill'
          sid = val || false
        when "-K", "--kill-all"
          method = 'killall'
        # Run a script or module on specified sessions
        when "-s", "--script"
          unless script
            method = 'script'
            script = val
            # Assume any parameter after the script name is a flag/argument we want to pass to the script itself.
            extra += args[(idx + 1)..-1]
            has_script_arguments = true
          end
        # Upload and exec to the specific command session
        when "-u", "--upgrade"
          method = 'upexec'
          sid = val || false
        # Search for specific session
        when "-S", "--search"
          search_term = val
        # Display help banner
        when "-h", "--help"
          cmd_sessions_help
          return false
        when "-t", "--timeout"
          if val.to_s =~ /^\d+$/
            response_timeout = val.to_i
          end
        when "-n", "--name"
          method = 'name'
          session_name = val
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
        print_error('Please specify valid session identifier(s)')
        return false
      end
    end

    if show_inactive && !framework.db.active
      print_warning("Database not connected; list of inactive sessions unavailable")
    end

    if search_term
      matching_sessions = get_matching_sessions(search_term)

      # check for nil value indicating validation has found invalid input in search helper functions. Error will have been printed already
      unless matching_sessions
        return nil
      end

      if matching_sessions.empty?
        print_error('No matching sessions.')
        return nil
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
        elsif matching_sessions
          sessions = matching_sessions
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
            case session.type.downcase
            when 'meterpreter'
              # If session.sys is nil, dont even try..
              unless session.sys
                print_error("Session #{s} does not have stdapi loaded, skipping...")
                next
              end
              c, c_args = cmd.split(' ', 2)
              begin
                data = session.sys.process.capture_output(c, c_args,
                {
                  'Channelized' => true,
                  'Subshell'    => true,
                  'Hidden'      => true
                }, response_timeout)
                print_line(data) unless data.blank?
              rescue ::Rex::Post::Meterpreter::RequestError
                print_error("Failed: #{$!.class} #{$!}")
              rescue ::Rex::TimeoutError
                print_error("Operation timed out. Timeout currently #{session.response_timeout} seconds, you can configure this with %grnsessions -c <cmd> --timeout <value>%clr")
              end
            when 'shell', 'powershell'
              output = session.shell_command(cmd)
              print_line(output) if output
            when 'mssql', 'postgresql', 'mysql'
              session.run_cmd(cmd, driver.output)
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
            begin
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
                session.on_run_command_error_proc = log_on_timeout_error("Send timed out. Timeout currently #{session.response_timeout} seconds, you can configure this with %grnsessions -C <cmd> --timeout <value>%clr")
              end

              output = session.run_cmd(cmd, driver.output)
            ensure
              if session.respond_to?(:response_timeout) && last_known_timeout
                session.response_timeout = last_known_timeout
                session.on_run_command_error_proc = nil
              end
            end
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
      if matching_sessions
        print_status('Killing matching sessions...')
        print_line
        print(Serializer::ReadableText.dump_sessions(framework, show_active: show_active, show_inactive: show_inactive, show_extended: show_extended, verbose: verbose, sessions: matching_sessions))
        print_line
      else
        matching_sessions = framework.sessions
        print_status('Killing all sessions...')
      end
      matching_sessions.each do |_session_id, session|
        next unless session

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
    when 'interact'
      while sid
        session = verify_session(sid)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
            session.on_run_command_error_proc = log_on_timeout_error("Send timed out. Timeout currently #{session.response_timeout} seconds, you can configure this with %grnsessions --interact <id> --timeout <value>%clr")
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
              session.on_run_command_error_proc = nil
            end
          end
        else
          sid = nil
        end
      end
    when 'script'
      unless script
        print_error("No script or module specified!")
        return false
      end
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
            session.on_run_command_error_proc = log_on_timeout_error("Send timed out. Timeout currently #{session.response_timeout} seconds, you can configure this with %grnsessions --timeout <value> --script <script> <id>%clr")
          end
          begin
            print_status("Session #{sess_id} (#{session.session_host}):")
            print_status("Running #{script} on #{session.type} session" +
                          " #{sess_id} (#{session.session_host})")
            begin
              session.init_ui(driver.input, driver.output)
              session.execute_script(script, *extra)
            rescue ::Exception => e
              log_error("Error executing script or module: #{e.class} #{e}")
            end
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
              session.on_run_command_error_proc = nil
            end
            session.reset_ui
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
            session.init_ui(driver.input, driver.output)
            session.execute_script('post/multi/manage/shell_to_meterpreter')
            session.reset_ui
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
    when 'list', 'list_inactive', nil
      print_line
      print(Serializer::ReadableText.dump_sessions(framework, show_active: show_active, show_inactive: show_inactive, show_extended: show_extended, verbose: verbose, sessions: matching_sessions))
      print_line
    when 'name'
      if session_name.blank?
        print_error('Please specify a valid session name')
        return false
      end

      sessions = sid ? session_list : nil

      if sessions.nil? || sessions.empty?
        print_error("Please specify valid session identifier(s) using -i")
        return false
      end

      sessions.each do |s|
        if framework.sessions[s].respond_to?(:name=)
          framework.sessions[s].name = session_name
          print_status("Session #{s} named to #{session_name}")
        else
          print_error("Session #{s} cannot be named")
        end
      end
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

  def get_matching_sessions(search_term)
    matching_sessions = {}
    terms = search_term.split
    id_searches = []
    type_searches = []
    checkin_searches = []
    searches = []

    # Group search terms by what's being searched for
    terms.each do |term|
      case term.split(':').first
      when SESSION_ID
        id_searches << term
      when SESSION_TYPE
        type_searches << term
      when LAST_CHECKIN
        checkin_searches << term
      else
        print_error("Please provide valid search term. Given: #{term.split(':').first}. Supported keywords are: #{VALID_SESSION_SEARCH_PARAMS.join(', ')}")
        return nil
      end
    end

    # Group results by search term - OR filters
    [id_searches, type_searches].each do |search|
      next if search.empty?

      id_matches = {}
      search.each do |term|
        matches = filter_sessions_by_search(term)
        return unless matches

        id_matches = id_matches.merge(matches)
      end
      searches << id_matches
    end

    # Retrieve checkin search results. AND filter with a max length of 2
    unless checkin_searches.empty?
      unless validate_checkin_searches(checkin_searches)
        return
      end

      checkin_matches = filter_sessions_by_search(checkin_searches.first)
      if checkin_searches[1]
        matches = filter_sessions_by_search(checkin_searches[1])
        checkin_matches = checkin_matches.select { |session_id, session| matches[session_id] == session }
      end
      searches << checkin_matches
    end

    # AND all the results together for final session list
    if searches.empty?
      print_error('Please provide a valid search query.')
      return nil
    else
      matching_sessions = searches.first
      searches[1..].each do |result_set|
        matching_sessions = matching_sessions.select { |session_id, session| result_set[session_id] == session }
      end
    end
    matching_sessions
  end

  def validate_checkin_searches(checkin_searches)
    checkin_searches.each do |search_term|
      unless search_term.split(':').length == 3
        print_error('Please only specify last_checkin, before or after, and a time. Ex: last_checkin:before:1m30s')
        return false
      end
      time_value = search_term.split(':')[2]
      time_unit_string = time_value.gsub(/[^a-zA-Z]/, '')
      unless time_unit_string == time_unit_string.squeeze
        print_error('Please do not provide duplicate time units in your query')
        return false
      end
      operator = checkin_searches[0].split(':')[1]
      unless VALID_OPERATORS.include?(operator)
        print_error("Please specify less_than or greater_than for checkin query. Ex: last_checkin:less_than:1m30s. Given: #{operator}")
        return false
      end
    end
    if checkin_searches.length > 2
      print_error("Too many checkin searches. Max: 2. Given: #{checkin_searches.length}")
      return false
    elsif checkin_searches.length == 2
      _, operator1, value1 = checkin_searches[0].split(':')
      _, operator2, value2 = checkin_searches[1].split(':')
      unless VALID_OPERATORS.include?(operator1) && VALID_OPERATORS.include?(operator2)
        print_error('last_checkin can only be searched for using before or after. Ex: last_checkin:before:1m30s')
        return false
      end
      if operator1 == operator2
        print_error("Cannot search for last_checkin with two #{operator1} arguments.")
        return false
      end
      if (operator1 == GREATER_THAN && parse_duration(value2) < parse_duration(value1)) || (operator1 == LESS_THAN && parse_duration(value1) < parse_duration(value2))
        print_error('After value must be a larger duration than the before value.')
        return false
      end
    end
    true
  end

  def filter_sessions_by_search(search_term)
    matching_sessions = {}
    field, = search_term.split(':')
    framework.sessions.each do |session_id, session|
      if !session.respond_to?(:last_checkin) && (field == LAST_CHECKIN)
        next
      end

      matches_search = evaluate_search_criteria(session, search_term)
      return nil if matches_search.nil?

      case field
      when LAST_CHECKIN
        if session.last_checkin && evaluate_search_criteria(session, search_term)
          matching_sessions[session_id] = session
        end
      when SESSION_TYPE, SESSION_ID
        matching_sessions[session_id] = session if evaluate_search_criteria(session, search_term)
      else
        print_error("Unrecognized search term: #{field}")
        return nil
      end
    end
    matching_sessions
  end

  def evaluate_search_criteria(session, search_term)
    field, operator, value = search_term.split(':')

    case field
    when LAST_CHECKIN
      last_checkin_time = session.last_checkin
      offset = parse_duration(value)
      return nil unless offset

      threshold_time = Time.now - offset
      case operator
      when GREATER_THAN
        return threshold_time > last_checkin_time
      when LESS_THAN
        return threshold_time < last_checkin_time
      end
    when SESSION_ID
      return session.sid.to_s == operator
    when SESSION_TYPE
      return session.type.casecmp?(operator)
    end
  end

  def parse_duration(duration)
    total_time = 0
    time_tokens = duration.scan(/(?:\d+\.?\d*|\.\d+)/).zip(duration.scan(/[a-zA-Z]+/))
    time_tokens.each do |value, unit|
      if unit.nil? || value.nil?
        print_error('Please specify both time units and amounts')
        return nil
      end
      case unit.downcase
      when 'd'
        total_time += value.to_f * 86400
      when 'h'
        total_time += value.to_f * 3600
      when 'm'
        total_time += value.to_f * 60
      when 's'
        total_time += value.to_f
      else
        print_error("Unrecognized time format: #{value}")
        return nil
      end
    end
    total_time.to_i
  end

  #
  # Tab completion for the sessions command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_sessions_tabs(str, words)
    if words.length == 1
      return @@sessions_opts.option_keys.select { |opt| opt.start_with?(str) }
    end

    case words[-1]
    when "-i", "--interact", "-k", "--kill", "-u", "--upgrade"
      return framework.sessions.keys.map { |k| k.to_s }

    when "-c", "--command"
      # Can't really complete commands hehe

    when "-s", "--search"
      # XXX: Complete scripts

    end

    []
  end

  def cmd_set_help
    print_line "Usage: set [options] [name] [value]"
    print_line
    print_line "Set the given option to value.  If value is omitted, print the current value."
    print_line "If both are omitted, print options that are currently set."
    print_line
    print_line "If run from a module context, this will set the value in the module's"
    print_line "datastore.  Use -g to operate on the global datastore."
    print_line
    print_line "If setting a PAYLOAD, this command can take an index from `show payloads'."
    print @@set_opts.usage
    print_line
  end

  #
  # Sets a name to a value in a context aware environment.
  #
  def cmd_set(*args)
    # Figure out if these are global variables
    global = false
    append = false
    clear = false

    # Manually parse options to allow users to set the strings
    # such as `-g` in a datastore value
    loop do
      if args[0] == '-g' || args[0] == '--global'
        args.shift
        global = true
      elsif args[0] == '-a'
        args.shift
        append = true
      elsif (args[0] == '-c' || args[0] == '--clear')
        args.shift
        clear = true
      else
        break
      end
    end

    valid_options = []
    # Determine which data store we're operating on
    if (active_module and global == false)
      datastore = active_module.datastore

      tab_complete_option_names(active_module, '', []).each do |opt_name|
        valid_options << opt_name
        option = active_module.options[opt_name]
        next unless option

        # aliases that are defined for backwards compatibility are not tab completed but are still valid option names
        valid_options += active_module.options[opt_name].aliases
      end
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
    elsif args.length == 1 && !clear
      if global || valid_options.any? { |vo| vo.casecmp?(args[0]) }
        print_line("#{args[0]} => #{datastore[args[0]]}")
        return true
      else
        message = "Unknown datastore option: #{args[0]}."
        suggestion = DidYouMean::SpellChecker.new(dictionary: valid_options).correct(args[0]).first
        message << " Did you mean #{suggestion}?" if suggestion
        print_error(message)
        cmd_set_help
        return false
      end
    end

    # Set the supplied name to the supplied value
    name, *values_array = args
    if clear
      value = nil
    elsif name.casecmp?('RHOST') || name.casecmp?('RHOSTS')
      # Wrap any values which contain spaces in quotes to ensure it's parsed correctly later
      value = values_array.map { |value| value.include?(' ') ? "\"#{value}\"" : value }.join(' ')
    else
      value = values_array.join(' ')
    end

    # Set PAYLOAD
    if name.upcase == 'PAYLOAD' && active_module && (active_module.exploit? || active_module.evasion?) && !clear
      value = trim_path(value, 'payload')

      index_from_list(payload_show_results, value) do |mod|
        return false unless mod && mod.respond_to?(:first)

        # [name, class] from payload_show_results
        value = mod.first
      end
    end

    unless global || valid_options.any? { |vo| vo.casecmp?(name) }
      message = "Unknown datastore option: #{name}."
      suggestion = DidYouMean::SpellChecker.new(dictionary: valid_options).correct(name).first
      message << " Did you mean #{suggestion}?" if suggestion
      print_warning(message)
    end

    # If the driver indicates that the value is not valid, bust out.
    if (driver.on_variable_set(global, name, value) == false)
      print_error("The value specified for #{name} is not valid.")
      return false
    end

    # Save the old value before changing it, in case we need to compare it
    old_value = datastore[name]

    begin
      if append
        datastore[name] = datastore[name] + value
      else
        datastore[name] = value
      end
    rescue Msf::OptionValidateError => e
      print_error(e.message)
      elog('Exception encountered in cmd_set', error: e)
    end

    # Set PAYLOAD from TARGET
    if name.upcase == 'TARGET' && active_module && (active_module.exploit? || active_module.evasion?)
      active_module.import_target_defaults
    end

    # If the new SSL value already set in datastore[name] is different from the old value, warn the user
    if name.casecmp('SSL') == 0 && datastore[name] != old_value
      print_warning("Changing the SSL option's value may require changing RPORT!")
    end

    if name.casecmp?('SessionTlvLogging')
      # Check if we need to append the default filename if user provided an output directory
      if datastore[name].start_with?('file:')
        pathname = ::Pathname.new(datastore[name].split('file:').last)
        if ::File.directory?(pathname)
          datastore[name] = ::File.join(datastore[name], 'sessiontlvlogging.txt')
        end
      end

      framework.sessions.each { |_index, session| session.initialize_tlv_logging(datastore[name]) if session.type.casecmp? 'meterpreter' }
    end

    print_line("#{name} => #{datastore[name]}")
  end

  def payload_show_results
    Msf::Ui::Console::CommandDispatcher::Modules.class_variable_get(:@@payload_show_results)
  end

  #
  # Tab completion for the set command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_set_tabs(str, words)
    # A value has already been specified
    if words.length > 3
      return []
    elsif words.length == 3 and words[1] != '-g' and words[1] != '--global'
      return []
    end

    # A value needs to be specified, show tab completion options where possible
    if words.length == 3 or (words.length == 2 and words[1][0] != '-')
      return tab_complete_option_values(active_module, str, words, opt: words[-1])
    end

    option_names = tab_complete_option_names(active_module, str, words)
    if words.length == 1
      # Only the command has been provided, offer options which immediately follow the command
      options = @@set_opts.option_keys.select { |opt| opt.start_with?(str) }
      return options + option_names
    end

    option_names
  end

  def cmd_setg_help
    print_line "Usage: setg [option] [value]"
    print_line
    print_line "Exactly like set -g, set a value in the global datastore."
    print @@setg_opts.usage
    print_line
  end

  #
  # Tab completion for the unset command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command
  #   line. `words` is always at least 1 when tab completion has reached this
  #   stage since the command itself has been completed.
  def cmd_unset_tabs(str, words)
    datastore_names = tab_complete_module_datastore_names(active_module, str, words)
    if words.length == 1
      # Only the command has been provided, offer options which immediately follow the command
      options = @@unset_opts.option_keys.select { |opt| opt.start_with?(str) }
      return options + datastore_names
    end

    datastore_names
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
    print_line "To flush all entries, specify 'all' as the variable name."
    print_line "With -g, operates on global datastore variables."
    print_line
  end

  #
  # Unsets a value if it's been set.
  #
  def cmd_unset(*args)
    if args.include?('-h') || args.include?('--help')
      cmd_unset_help
      return
    end

    # Figure out if these are global variables
    global = false

    @@unset_opts.parse(args) do |opt, idx, val|
      case opt
      when '-g'
        global = true
      end
    end

    variable_names = args.reject { |arg| arg.start_with?('-') }

    # No variable names? No cookie.
    if variable_names.empty?
      cmd_unset_help
      return false
    end

    # Determine which data store we're operating on
    if active_module && !global
      datastore = active_module.datastore
    else
      datastore = framework.datastore
    end

    is_all_variables = variable_names[0] == 'all'
    if is_all_variables
      variable_names = datastore.keys
      variable_names += Msf::DataStore::GLOBAL_KEYS if global
      variable_names += ['PAYLOAD'] if !global && active_module && (active_module.exploit? || active_module.evasion?)
      variable_names = variable_names.uniq(&:downcase)
    end

    print_line("Unsetting datastore...") if is_all_variables

    variable_names.each do |variable_name|
      if driver.on_variable_unset(global, variable_name) == false
        print_error("The variable #{variable_name} cannot be unset at this time.") # unless variable_name.casecmp?('PAYLOAD')
        next
      end

      print_line("Unsetting #{variable_name}...") unless is_all_variables
      datastore.unset(variable_name)
    end

    # Do a final pass over the datastore. If a user has unset a variable - but it continues to have a value either through
    # option defaults, or being globally set it might be confusing to users. In this scenario, log out a helpful message.
    #
    # i.e. the scenario of a user unsetting 'RHOSTS', but the value continues to inherit from the global framework datastore.
    unless is_all_variables
      variable_names.each do |variable_name|
        search_result = datastore.search_for(variable_name)
        if search_result.fallback?
          print_warning(
            "Variable #{variable_name.inspect} unset - but will continue to use #{search_result.fallback_key.inspect} as a fallback preference. " \
              "If this is not desired, either run #{Msf::Ui::Tip.highlight("set #{variable_name} new_value")} or #{Msf::Ui::Tip.highlight("unset #{search_result.fallback_key}")}"
          )
        elsif !global && search_result.global?
          print_warning(
            "Variable #{variable_name.inspect} unset - but will continue to use the globally set value as a preference. " \
              "If this is not desired, either run #{Msf::Ui::Tip.highlight("set --clear #{variable_name}")} or #{Msf::Ui::Tip.highlight("unsetg #{variable_name}")}"
          )
        elsif !search_result.value.nil?
          print_warning(
            "Variable #{variable_name.inspect} unset - but will use a default value still. " \
              "If this is not desired, set it to a new value or attempt to clear it with #{Msf::Ui::Tip.highlight("set --clear #{variable_name}")}"
          )
        end
      end
    end
  end

  def cmd_unsetg_help
    print_line "Usage: unsetg [options] var1 var2 var3 ..."
    print_line
    print_line "Exactly like unset -g, unset global variables, or all"
    print @@unsetg_opts.usage
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
    tab_complete_datastore_names(framework.datastore, str, words)
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
    cmd_grep '-h'
  end

  #
  # Greps the output of another console command, usage is similar the shell grep command
  # grep [options] pattern other_cmd [other command's args], similar to the shell's grep [options] pattern file
  # however it also includes -k to keep lines and -s to skip lines.  grep -k 5 is useful for keeping table headers
  #
  # @param args [Array<String>] Args to the grep command minimally including a pattern & a command to search
  # @return [String,nil] Results matching the regular expression given

  def cmd_grep(*args)
    match_mods = {:insensitive => false}
    output_mods = {:count => false, :invert => false}

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: grep [OPTIONS] [--] PATTERN CMD..."
      opts.separator "Grep the results of a console command (similar to Linux grep command)"
      opts.separator ""

      opts.on '-m num', '--max-count num', 'Stop after num matches.', Integer do |max|
        match_mods[:max] = max
      end
      opts.on '-A num', '--after-context num', 'Show num lines of output after a match.', Integer do |num|
        output_mods[:after] = num
      end
      opts.on '-B num', '--before-context num', 'Show num lines of output before a match.', Integer do |num|
        output_mods[:before] = num
      end
      opts.on '-C num', '--context num', 'Show num lines of output around a match.', Integer do |num|
        output_mods[:before] = output_mods[:after] = num
      end
      opts.on '-v', '--[no-]invert-match', 'Invert match.' do |invert|
        match_mods[:invert] = invert
      end
      opts.on '-i', '--[no-]ignore-case', 'Ignore case.' do |insensitive|
        match_mods[:insensitive] = insensitive
      end
      opts.on '-c', '--count', 'Only print a count of matching lines.' do |count|
        output_mods[:count] = count
      end
      opts.on '-k num', '--keep-header num', 'Keep (include) num lines at start of output', Integer do |num|
        output_mods[:keep] = num
      end
      opts.on '-s num', '--skip-header num', 'Skip num lines of output before attempting match.', Integer do |num|
        output_mods[:skip] = num
      end
      opts.on '-h', '--help', 'Help banner.' do
        return print(remove_lines(opts.help, '--generate-completions'))
      end

      # Internal use
      opts.on '--generate-completions str', 'Return possible tab completions for given string.' do |str|
        return opts.candidate str
      end
    end

    # OptionParser#order allows us to take the rest of the line for the command
    pattern, *rest = opts.order(args)
    cmd = Shellwords.shelljoin(rest)
    return print(opts.help) if !pattern || cmd.empty?

    rx = Regexp.new(pattern, match_mods[:insensitive])

    # redirect output after saving the old one and getting a new output buffer to use for redirect
    orig_output = driver.output

    # we use a rex buffer but add a write method to the instance, which is
    # required in order to be valid $stdout
    temp_output = Rex::Ui::Text::Output::Buffer.new
    temp_output.extend Rex::Ui::Text::Output::Buffer::Stdout

    driver.init_ui(driver.input, temp_output)
    # run the desired command to be grepped
    driver.run_single(cmd)
    # restore original output
    driver.init_ui(driver.input, orig_output)

    # dump the command's output so we can grep it
    cmd_output = temp_output.dump_buffer

    # Bail if the command failed
    if cmd_output =~ /Unknown command:/
      print_error("Unknown command: '#{rest[0]}'.")
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
      # we don't want to keep processing if we have a :max and we've reached it already (not counting skips/keeps)
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
    str = '-' if str.empty? # default to use grep's options
    tabs = cmd_grep '--generate-completions', str

    # if not an opt, use normal tab comp.
    # @todo uncomment out next line when tab_completion normalization is complete RM7649 or
    # replace with new code that permits "nested" tab completion
    # tabs = driver.get_all_commands if (str and str =~ /\w/)
    tabs
  end

  def cmd_repeat_help
    cmd_repeat '-h'
  end

  #
  # Repeats (loops) a given list of commands
  #
  def cmd_repeat(*args)
    looper = method :loop

    opts = OptionParser.new do |opts|
      opts.banner = 'Usage: repeat [OPTIONS] COMMAND...'
      opts.separator 'Repeat (loop) a ;-separated list of msfconsole commands indefinitely, or for a'
      opts.separator 'number of iterations or a certain amount of time.'
      opts.separator ''

      opts.on '-t SECONDS', '--time SECONDS', 'Number of seconds to repeat COMMAND...', Integer do |n|
        looper = ->(&block) do
          # While CLOCK_MONOTONIC is a Linux thing, Ruby emulates it for *BSD, MacOS, and Windows
          ending_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :second) + n
          while Process.clock_gettime(Process::CLOCK_MONOTONIC, :second) < ending_time
            block.call
          end
        end
      end

      opts.on '-n TIMES', '--number TIMES', 'Number of times to repeat COMMAND..', Integer do |n|
        looper = n.method(:times)
      end

      opts.on '-h', '--help', 'Help banner.' do
        return print(remove_lines(opts.help, '--generate-completions'))
      end

      # Internal use
      opts.on '--generate-completions str', 'Return possible tab completions for given string.' do |str|
        return opts.candidate str
      end
    end

    cmds = opts.order(args).slice_when do |prev, _|
      # If the last character of a shellword was a ';' it's probably to
      # delineate commands and we can remove it
      prev[-1] == ';' && prev[-1] = ''
    end.map do |c|
      Shellwords.shelljoin(c)
    end

    # Print help if we have no commands, or all the commands are empty
    return cmd_repeat '-h' if cmds.all? &:empty?

    begin
      looper.call do
        cmds.each do |c|
          driver.run_single c, propagate_errors: true
        end
      end
    rescue ::Exception
      # Stop looping on exception
      nil
    end
  end

  # Almost the exact same as grep
  def cmd_repeat_tabs(str, words)
    str = '-' if str.empty? # default to use repeat's options
    tabs = cmd_repeat '--generate-completions', str

    # if not an opt, use normal tab comp.
    # @todo uncomment out next line when tab_completion normalization is complete RM7649 or
    # replace with new code that permits "nested" tab completion
    # tabs = driver.get_all_commands if (str and str =~ /\w/)
    tabs
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

  #
  # Custom error code to handle timeout errors
  #
  # @param message [String] The message to be printed when a timeout error is hit
  # @return [Proc] proc function that prints the specified error when the error types match
  def log_on_timeout_error(message)
    proc do |e|
      next unless e.is_a?(Rex::TimeoutError) || e.is_a?(Timeout::Error)
      elog(e)
      print_error(message)
      :handled
    end
  end

  #
  # Returns an array of lines at the provided line number plus any before and/or after lines requested
  # from all_lines by supplying the +before+ and/or +after+ parameters which are always positive
  #
  # @param all_lines [Array<String>] An array of all lines being considered for matching
  # @param line_num [Integer] The line number in all_lines which has satisfied the match
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
