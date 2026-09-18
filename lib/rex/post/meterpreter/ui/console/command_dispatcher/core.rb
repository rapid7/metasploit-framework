# -*- coding: binary -*-
require 'set'
require 'yaml'
require 'rex/post/meterpreter'
require 'rex/post/meterpreter/micro_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/micro_alias'
require 'rex'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Core meterpreter client commands that provide only the required set of
# commands for having a functional meterpreter client<->server instance.
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
    @micro_dispatchers = {}
    @micro_helpers = {}
    @micro_manifest_commands = {}
    @micro_command_aliases = {}
    @micro_alias_dispatcher = nil

    # keep a lookup table to refer to transports by index
    @transport_map = {}
  end

  @@load_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help menu.'                    ],
    '-l' => [false, 'List all available extensions.']
  )

  #
  # List of supported commands.
  #
  def commands
    cmds = {
      '?'                        => 'Help menu',
      'background'               => 'Backgrounds the current session',
      'bg'                       => 'Alias for background',
      'close'                    => 'Closes a channel',
      'channel'                  => 'Displays information or control active channels',
      'exit'                     => 'Terminate the meterpreter session',
      'help'                     => 'Help menu',
      'irb'                      => 'Open an interactive Ruby shell on the current session',
      'pry'                      => 'Open the Pry debugger on the current session',
      'use'                      => 'Deprecated alias for "load"',
      'load'                     => 'Load one or more meterpreter extensions',
      'machine_id'               => 'Get the MSF ID of the machine attached to the session',
      'secure'                   => '(Re)Negotiate TLV packet encryption on the session',
      'guid'                     => 'Get the session GUID',
      'quit'                     => 'Terminate the meterpreter session',
      'resource'                 => 'Run the commands stored in a file',
      'uuid'                     => 'Get the UUID for the current session',
      'read'                     => 'Reads data from a channel',
      'run'                      => 'Executes a meterpreter script or Post module',
      'bgrun'                    => 'Executes a meterpreter script as a background thread',
      'bgkill'                   => 'Kills a background meterpreter script',
      'sessions'                 => 'Quickly switch to another session',
      'bglist'                   => 'Lists running background scripts',
      'write'                    => 'Writes data to a channel',
      'enable_unicode_encoding'  => 'Enables encoding of unicode strings',
      'disable_unicode_encoding' => 'Disables encoding of unicode strings',
      'migrate'                  => 'Migrate the server to another process',
      'micro'                    => 'Manage Meterpreter microextensions',
      'pivot'                    => 'Manage pivot listeners',
      # transport related commands
      'detach'                   => 'Detach the meterpreter session (for http/https)',
      'sleep'                    => 'Force Meterpreter to go quiet, then re-establish session',
      'transport'                => 'Manage the transport mechanisms',
      'get_timeouts'             => 'Get the current session timeout values',
      'set_timeouts'             => 'Set the current session timeout values',
      'ssl_verify'               => 'Modify the SSL certificate verification setting'
    }

    if msf_loaded?
      cmds['info'] = 'Displays information about a Post module'
    end
    reqs = {
      'load'         => [COMMAND_ID_CORE_LOADLIB],
      'machine_id'   => [COMMAND_ID_CORE_MACHINE_ID],
      'migrate'      => [COMMAND_ID_CORE_MIGRATE],
      'pivot'        => [COMMAND_ID_CORE_PIVOT_ADD, COMMAND_ID_CORE_PIVOT_REMOVE],
      'secure'       => [COMMAND_ID_CORE_NEGOTIATE_TLV_ENCRYPTION],
      # channel related commands
      'read'         => [COMMAND_ID_CORE_CHANNEL_READ],
      'write'        => [COMMAND_ID_CORE_CHANNEL_WRITE],
      'close'        => [COMMAND_ID_CORE_CHANNEL_CLOSE],
      # transport related commands
      'sleep'        => [COMMAND_ID_CORE_TRANSPORT_SLEEP],
      'ssl_verify'   => [COMMAND_ID_CORE_TRANSPORT_GETCERTHASH, COMMAND_ID_CORE_TRANSPORT_SETCERTHASH],
      'transport'    => [
        COMMAND_ID_CORE_TRANSPORT_ADD,
        COMMAND_ID_CORE_TRANSPORT_CHANGE,
        COMMAND_ID_CORE_TRANSPORT_LIST,
        COMMAND_ID_CORE_TRANSPORT_NEXT,
        COMMAND_ID_CORE_TRANSPORT_PREV,
        COMMAND_ID_CORE_TRANSPORT_REMOVE
      ],
      'get_timeouts' => [COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS],
      'set_timeouts' => [COMMAND_ID_CORE_TRANSPORT_SET_TIMEOUTS],
    }

    # XXX: Remove this line once the payloads gem has had another major version bump from 2.x to 3.x and
    # rapid7/metasploit-payloads#451 has been landed to correct the `enumextcmd` behavior on Windows. Until then, skip
    # filtering for Windows which supports all the filtered commands anyways. This is not the only instance of this
    # workaround.
    reqs.clear if client.base_platform == 'windows'
    reqs['micro'] = [COMMAND_ID_CORE_MICRO_HAS_COMMAND, COMMAND_ID_CORE_MICRO_LOAD, COMMAND_ID_CORE_MICRO_ENUM, COMMAND_ID_CORE_MICRO_UNLOAD]

    filter_commands(cmds, reqs)
  end

  #
  # Core baby.
  #
  def name
    'Core'
  end

  @@pivot_opts = Rex::Parser::Arguments.new(
    '-t' => [true, 'Pivot listener type'],
    '-i' => [true, 'Identifier of the pivot to remove'],
    '-l' => [true, 'Host address to bind to (if applicable)'],
    '-n' => [true, 'Name of the listener entity (if applicable)'],
    '-a' => [true, 'Architecture of the stage to generate'],
    '-p' => [true, 'Platform of the stage to generate'],
    '-h' => [false, 'View help']
  )

  @@pivot_supported_archs = [Rex::Arch::ARCH_X64, Rex::Arch::ARCH_X86]
  @@pivot_supported_platforms = ['windows']

  def cmd_pivot_help
    print_line('Usage: pivot <list|add|remove> [options]')
    print_line
    print_line('Manage pivot listeners on the target.')
    print_line
    print_line(@@pivot_opts.usage)
    print_line
    print_line('Supported pivot types:')
    print_line('     - pipe (using named pipes over SMB)')
    print_line('Supported architectures:')
    @@pivot_supported_archs.each do |a|
      print_line('     - ' + a)
    end
    print_line('Supported platforms:')
    print_line('     - windows')
    print_line
    print_line("eg.    pivot add -t pipe -l 192.168.0.1 -n msf-pipe -a #{@@pivot_supported_archs.first} -p windows")
    print_line("       pivot list")
    print_line("       pivot remove -i 1")
    print_line
  end

  def cmd_pivot_tabs(str, words)
    return %w[list add remove] + @@pivot_opts.option_keys if words.length == 1

    case words[-1]
    when '-a'
      return @@pivot_supported_archs
    when '-i'
      matches = []
      client.pivot_listeners.each_value { |v| matches << v.id.unpack('H*')[0] }
      return matches
    when '-p'
      return @@pivot_supported_platforms
    when '-t'
      return ['pipe']
    when 'add', 'remove'
      return @@pivot_opts.option_keys
    end

    []
  end

  def cmd_pivot(*args)
    if args.length == 0 || args.include?('-h')
      cmd_pivot_help
      return true
    end

    opts = {}
    @@pivot_opts.parse(args) { |opt, idx, val|
      case opt
      when '-t'
        opts[:type] = val
      when '-i'
        opts[:guid] = val
      when '-l'
        opts[:lhost] = val
      when '-n'
        opts[:name] = val
      when '-a'
        opts[:arch] = val
      when '-p'
        opts[:platform] = val
      end
    }

    # first parameter is the command
    case args[0]
    when 'remove', 'del', 'delete', 'rm'
      unless opts[:guid]
        print_error('Pivot listener ID must be specified (-i)')
        return false
      end

      unless opts[:guid] =~ /^[0-9a-f]{32}/i && opts[:guid].length == 32
        print_error("Invalid pivot listener ID: #{opts[:guid]}")
        return false
      end

      listener_id = [opts[:guid]].pack('H*')
      unless client.find_pivot_listener(listener_id)
        print_error("Unknown pivot listener ID: #{opts[:guid]}")
        return false
      end

      Pivot.remove_listener(client, listener_id)
      print_good("Successfully removed pivot: #{opts[:guid]}")
    when 'list', 'show', 'print'
      if client.pivot_listeners.length > 0
        tbl = Rex::Text::Table.new(
          'Header'  => 'Currently active pivot listeners',
          'Indent'  => 4,
          'Columns' => ['Id', 'URL', 'Stage'])

        client.pivot_listeners.each do |k, v|
          tbl << v.to_row
        end
        print_line
        print_line(tbl.to_s)
      else
        print_status('There are no active pivot listeners')
      end
    when 'add'
      unless opts[:type]
        print_error('Pivot type must be specified (-t)')
        return false
      end

      unless opts[:arch]
        print_error('Architecture must be specified (-a)')
        return false
      end
      unless @@pivot_supported_archs.include?(opts[:arch])
        print_error("Unknown or unsupported architecture: #{opts[:arch]}")
        return false
      end

      unless opts[:platform]
        print_error('Platform must be specified (-p)')
        return false
      end
      unless @@pivot_supported_platforms.include?(opts[:platform])
        print_error("Unknown or unsupported platform: #{opts[:platform]}")
        return false
      end

      # currently only one pivot type supported, more to come we hope
      case opts[:type]
      when 'pipe'
        pivot_add_named_pipe(opts)
      else
        print_error("Unknown pivot type: #{opts[:type]}")
        return false
      end
    else
      print_error("Unknown command: #{args[0]}")
    end
  end

  def pivot_add_named_pipe(opts)
    unless opts[:lhost]
      print_error('Pipe host must be specified (-l)')
      return false
    end

    unless opts[:name]
      print_error('Pipe name must be specified (-n)')
      return false
    end

    # reconfigure the opts so that they can be passed to the setup function
    opts[:pipe_host] = opts[:lhost]
    opts[:pipe_name] = opts[:name]
    Pivot.create_named_pipe_listener(client, opts)
    print_good("Successfully created #{opts[:type]} pivot.")
  end

  def cmd_secure
    print_status('Negotiating new encryption key ...')
    client.core.secure
    print_good('Done.')
  end

  #
  # Displays information about active channels
  #
  @@channel_opts = Rex::Parser::Arguments.new(
    '-c' => [ true,  'Close the given channel.' ],
    '-k' => [ true,  'Close the given channel.' ],
    '-K' => [ false, 'Close all channels.' ],
    '-i' => [ true,  'Interact with the given channel.' ],
    '-l' => [ false, 'List active channels.' ],
    '-r' => [ true,  'Read from the given channel.' ],
    '-w' => [ true,  'Write to the given channel.' ],
    '-h' => [ false, 'Help menu.' ])

  def cmd_channel_help
    print_line('Usage: channel [options]')
    print_line
    print_line('Displays information about active channels.')
    print_line(@@channel_opts.usage)
  end

  #
  # Performs operations on the supplied channel.
  #
  def cmd_channel(*args)
    if args.empty? || args.include?('-h')
      cmd_channel_help
      return
    end

    mode = nil
    chan = nil

    # Parse options
    @@channel_opts.parse(args) { |opt, idx, val|
      case opt
      when '-l'
        mode = :list
      when '-c', '-k'
        mode = :close
        chan = val
      when '-i'
        mode = :interact
        chan = val
      when '-r'
        mode = :read
        chan = val
      when '-w'
        mode = :write
        chan = val
      when '-K'
        mode = :kill_all
      end

      if @@channel_opts.arg_required?(opt)
        unless chan
          print_error('Channel ID required')
          return
        end
      end
    }

    case mode
    when :list
      tbl = Rex::Text::Table.new(
        'Indent'  => 4,
        'Columns' => ['Id', 'Class', 'Type'])
      items = 0

      client.channels.each_pair { |cid, channel|
        tbl << [ cid, channel.class.cls, channel.type ]
        items += 1
      }

      if (items == 0)
        print_line('No active channels.')
      else
        print("\n" + tbl.to_s + "\n")
      end
    when :close
      cmd_close(chan)
    when :interact
      cmd_interact(chan)
    when :read
      cmd_read(chan)
    when :write
      cmd_write(chan)
    when :kill_all
      if client.channels.empty?
        print_line('No active channels.')
        return
      end

      print_line('Killing all channels...')
      client.channels.each_pair do |id, channel|
        channel._close
      rescue ::StandardError
        print_error("Failed when trying to kill channel: #{id}")
      end
      print_line('Killed all channels.')
    else
      # No mode, no service.
      return true
    end
  end

  def cmd_channel_tabs(str, words)
    case words.length
    when 1
      @@channel_opts.option_keys
    when 2
      case words[1]
      when '-k', '-c', '-i', '-r', '-w'
        tab_complete_channels
      else
        []
      end
    else
      []
    end
  end

  def cmd_close_help
    print_line('Usage: close <channel_id>')
    print_line
    print_line('Closes the supplied channel.')
    print_line
  end

  #
  # Closes a supplied channel.
  #
  def cmd_close(*args)
    if args.empty? || args.include?('-h')
      cmd_close_help
      return true
    end

    cid = args[0].to_i
    channel = client.find_channel(cid)

    unless channel
      print_error('Invalid channel identifier specified.')
      return true
    end

    channel._close # Issue #410

    print_status("Closed channel #{cid}.")
  end

  def cmd_close_tabs(str, words)
    return [] if words.length > 1

    return tab_complete_channels
  end

  def cmd_detach_help
    print_line('Detach from the victim. Only possible for non-stream sessions (http/https)')
    print_line
    print_line('The victim will continue to attempt to call back to the handler until it')
    print_line('successfully connects (which may happen immediately if you have a handler')
    print_line('running in the background), or reaches its expiration.')
    print_line
    print_line("This session may #{client.passive_service ? "" : "NOT"} be detached.")
    print_line
  end

  #
  # Disconnects the session
  #
  def cmd_detach(*args)
    unless client.passive_service
      print_error('The detach command is not applicable with the current transport')
      return
    end
    client.shutdown_passive_dispatcher
    shell.stop
  end

  def cmd_interact_help
    print_line('Usage: interact <channel_id>')
    print_line
    print_line('Interacts with the supplied channel.')
    print_line
  end

  #
  # Interacts with a channel.
  #
  def cmd_interact(*args)
    if args.empty? || args.include?('-h')
      cmd_info_help
      return true
    end

    cid = args[0].to_i
    channel = client.find_channel(cid)

    if channel
      print_line("Interacting with channel #{cid}...\n")

      shell.interact_with_channel(channel)
    else
      print_error('Invalid channel identifier specified.')
    end
  end

  alias cmd_interact_tabs cmd_close_tabs

  @@set_timeouts_opts = Rex::Parser::Arguments.new(
    '-c' => [true, 'Comms timeout (seconds)'],
    '-x' => [true, 'Expiration timeout (seconds)'],
    '-t' => [true, 'Retry total time (seconds)'],
    '-w' => [true, 'Retry wait time (seconds)'],
    '-h' => [false, 'Help menu'])

  def cmd_set_timeouts_help
    print_line('Usage: set_timeouts [options]')
    print_line
    print_line('Set the current timeout options.')
    print_line('Any or all of these can be set at once.')
    print_line(@@set_timeouts_opts.usage)
  end

  def cmd_set_timeouts_tabs(str, words)
    return [] if words.length > 1
    @@set_timeouts_opts.option_keys
  end

  def cmd_set_timeouts(*args)
    if args.length == 0 || args.include?('-h')
      cmd_set_timeouts_help
      return
    end

    opts = {}

    @@set_timeouts_opts.parse(args) do |opt, idx, val|
      case opt
      when '-c'
        opts[:comm_timeout] = val.to_i if val
      when '-x'
        opts[:session_exp] = val.to_i if val
      when '-t'
        opts[:retry_total] = val.to_i if val
      when '-w'
        opts[:retry_wait] = val.to_i if val
      end
    end

    if opts.keys.length == 0
      print_error('No options set')
    else
      timeouts = client.core.set_transport_timeouts(opts)
      print_timeouts(timeouts)
    end
  end

  def cmd_get_timeouts(*args)
    # Calling set without passing values is the same as
    # getting all the current timeouts
    timeouts = client.core.set_transport_timeouts
    print_timeouts(timeouts)
  end

  def print_timeouts(timeouts)
    if timeouts[:session_exp]
      print_line("Session Expiry  : @ #{(::Time.now + timeouts[:session_exp]).strftime('%Y-%m-%d %H:%M:%S')}")
    end
    if timeouts[:comm_timeout]
      print_line("Comm Timeout    : #{timeouts[:comm_timeout]} seconds")
    end
    if timeouts[:retry_total]
      print_line("Retry Total Time: #{timeouts[:retry_total]} seconds")
    end
    if timeouts[:retry_wait]
      print_line("Retry Wait Time : #{timeouts[:retry_wait]} seconds")
    end
  end

  #
  # Get the machine ID of the target
  #
  def cmd_machine_id(*args)
    client.machine_id = client.core.machine_id unless client.machine_id
    print_good("Machine ID: #{client.machine_id}")
  end

  #
  # Get the session GUID
  #
  def cmd_guid(*args)
    parts = client.session_guid.unpack('H*')[0]
    guid = [parts[0, 8], parts[8, 4], parts[12, 4], parts[16, 4], parts[20, 12]].join('-')
    print_good("Session GUID: #{guid}")
  end

  #
  # Get the machine ID of the target (should always be up to date locally)
  #
  def cmd_uuid(*args)
    print_good("UUID: #{client.payload_uuid}")
  end

  #
  # Arguments for ssl verification
  #
  @@ssl_verify_opts = Rex::Parser::Arguments.new(
    '-e' => [ false, 'Enable SSL certificate verification' ],
    '-d' => [ false, 'Disable SSL certificate verification' ],
    '-q' => [ false, 'Query the status of SSL certificate verification' ],
    '-h' => [ false, 'Help menu' ])

  #
  # Help for ssl verification
  #
  def cmd_ssl_verify_help
    print_line('Usage: ssl_verify [options]')
    print_line
    print_line('Change and query the current setting for SSL verification')
    print_line('Only one of the following options can be used at a time')
    print_line(@@ssl_verify_opts.usage)
  end

  #
  # Handle the SSL verification querying and setting function.
  #
  def cmd_ssl_verify(*args)
    if ( args.length == 0 or args.include?("-h") )
      cmd_ssl_verify_help
      return
    end

    unless client.passive_service && client.sock.type? == 'tcp-ssl'
      print_error('The ssl_verify command is not applicable with the current transport')
      return
    end

    query = false
    enable = false
    disable = false

    settings = 0

    @@ssl_verify_opts.parse(args) do |opt, idx, val|
      case opt
      when '-q'
        query = true
        settings += 1
      when '-e'
        enable = true
        settings += 1
      when '-d'
        disable = true
        settings += 1
      end
    end

    # Make sure only one action has been chosen
    if settings != 1
      cmd_ssl_verify_help
      return
    end

    if query
      hash = client.core.get_ssl_hash_verify
      if hash
        print_good("SSL verification is enabled. SHA1 Hash: #{hash.unpack("H*")[0]}")
      else
        print_good('SSL verification is disabled.')
      end

    elsif enable
      hash = client.core.enable_ssl_hash_verify
      if hash
        print_good("SSL verification has been enabled. SHA1 Hash: #{hash.unpack("H*")[0]}")
      else
        print_error('Failed to enable SSL verification')
      end

    else
      if client.core.disable_ssl_hash_verify
        print_good('SSL verification has been disabled')
      else
        print_error('Failed to disable SSL verification')
      end
    end

  end

  #
  # Display help for the sleep.
  #
  def cmd_sleep_help
    print_line('Usage: sleep <time>')
    print_line
    print_line('  time: Number of seconds to wait (positive integer)')
    print_line
    print_line('  This command tells Meterpreter to go to sleep for the specified')
    print_line('  number of seconds. Sleeping will result in the transport being')
    print_line('  shut down and restarted after the designated timeout.')
  end

  #
  # Handle the sleep command.
  #
  def cmd_sleep(*args)
    if args.empty? || args.include?('-h')
      cmd_sleep_help
      return
    end

    seconds = args.shift.to_i

    if seconds <= 0
      cmd_sleep_help
      return
    end

    print_status("Telling the target instance to sleep for #{seconds} seconds ...")
    if client.core.transport_sleep(seconds)
      print_good("Target instance has gone to sleep, terminating current session.")
      client.shutdown_passive_dispatcher
      shell.stop
    else
      print_error("Target instance failed to go to sleep.")
    end
  end

  #
  # Arguments for transport switching
  #
  @@transport_opts = Rex::Parser::Arguments.new(
    '-t' => [true, "Transport type: #{Rex::Post::Meterpreter::ClientCore::VALID_TRANSPORTS.keys.join(', ')}"],
    '-l' => [true, 'LHOST parameter (for reverse transports)'],
    '-p' => [true, 'LPORT parameter'],
    '-i' => [true, 'Specify transport by index (currently supported: remove)'],
    '-u' => [true, 'Local URI for HTTP/S transports (used when adding/changing transports with a custom LURI)'],
    '-c' => [true, 'SSL certificate path for https transport verification (optional)'],
    '-A' => [true, 'User agent for HTTP/S transports (optional)'],
    '-H' => [true, 'Proxy host for HTTP/S transports (optional)'],
    '-P' => [true, 'Proxy port for HTTP/S transports (optional)'],
    '-U' => [true, 'Proxy username for HTTP/S transports (optional)'],
    '-N' => [true, 'Proxy password for HTTP/S transports (optional)'],
    '-B' => [true, 'Proxy type for HTTP/S transports (optional: http, socks; default: http)'],
    '-C' => [true, 'Comms timeout (seconds) (default: same as current session)'],
    '-X' => [true, 'Expiration timeout (seconds) (default: same as current session)'],
    '-T' => [true, 'Retry total time (seconds) (default: same as current session)'],
    '-W' => [true, 'Retry wait time (seconds) (default: same as current session)'],
    '-v' => [false, 'Show the verbose format of the transport list'],
    '-h' => [false, 'Help menu'])

  #
  # Display help for transport management.
  #
  def cmd_transport_help
    print_line('Usage: transport <list|change|add|next|prev|remove> [options]')
    print_line
    print_line('   list: list the currently active transports.')
    print_line('    add: add a new transport to the transport list.')
    print_line(' change: same as add, but changes directly to the added entry.')
    print_line('   next: jump to the next transport in the list (no options).')
    print_line('   prev: jump to the previous transport in the list (no options).')
    print_line(' remove: remove an existing, non-active transport.')
    print_line(@@transport_opts.usage)
  end

  def cmd_transport_tabs(str, words)
    return %w[list change add next prev remove] + @@transport_opts.option_keys if words.length == 1

    case words[-1]
    when '-c'
      return tab_complete_filenames(str, words)
    when '-i'
      return (1..client.core.transport_list[:transports].length).to_a.map!(&:to_s)
    when '-l'
      return tab_complete_source_address
    when '-t'
      return %w[reverse_tcp reverse_http reverse_https bind_tcp]
    when 'add', 'remove', 'change'
      return @@transport_opts.option_keys
    end

    []
  end

  def update_transport_map
    result = client.core.transport_list
    @transport_map.clear
    sorted_by_url = result[:transports].sort_by { |k| k[:url] }
    sorted_by_url.each_with_index { |t, i| @transport_map[i+1] = t }
  end

  #
  # Manage transports
  #
  def cmd_transport(*args)
    if ( args.length == 0 or args.include?("-h") )
      cmd_transport_help
      return
    end

    command = args.shift
    unless ['list', 'add', 'change', 'prev', 'next', 'remove'].include?(command)
      cmd_transport_help
      return
    end

    opts = {
      :uuid         => client.payload_uuid,
      :transport    => nil,
      :lhost        => nil,
      :lport        => nil,
      :ua           => nil,
      :proxy_host   => nil,
      :proxy_port   => nil,
      :proxy_type   => nil,
      :proxy_user   => nil,
      :proxy_pass   => nil,
      :comm_timeout => nil,
      :session_exp  => nil,
      :retry_total  => nil,
      :retry_wait   => nil,
      :cert         => nil,
      :verbose      => false
    }

    valid = true
    transport_index = 0
    @@transport_opts.parse(args) do |opt, idx, val|
      case opt
      when '-c'
        opts[:cert] = val
      when '-i'
        transport_index = val.to_i
      when '-u'
        opts[:luri] = val
      when '-H'
        opts[:proxy_host] = val
      when '-P'
        opts[:proxy_port] = val.to_i
      when '-B'
        opts[:proxy_type] = val
      when '-U'
        opts[:proxy_user] = val
      when '-N'
        opts[:proxy_pass] = val
      when '-A'
        opts[:ua] = val
      when '-C'
        opts[:comm_timeout] = val.to_i if val
      when '-X'
        opts[:session_exp] = val.to_i if val
      when '-T'
        opts[:retry_total] = val.to_i if val
      when '-W'
        opts[:retry_wait] = val.to_i if val
      when '-p'
        opts[:lport] = val.to_i if val
      when '-l'
        opts[:lhost] = val
      when '-v'
        opts[:verbose] = true
      when '-t'
        unless client.core.valid_transport?(val)
          cmd_transport_help
          return
        end
        opts[:transport] = val
      else
        valid = false
      end
    end

    unless valid
      cmd_transport_help
      return
    end

    update_transport_map

    case command
    when 'list'
      result = client.core.transport_list

      current_transport_url = result[:transports].first[:url]

      sorted_by_url = result[:transports].sort_by { |k| k[:url] }

      # this will output the session timeout first
      print_timeouts(result)

      columns = ['ID', 'Curr', 'URL', 'Comms T/O', 'Retry Total', 'Retry Wait']

      if opts[:verbose]
        columns << 'User Agent'
        columns << 'Proxy Host'
        columns << 'Proxy User'
        columns << 'Proxy Pass'
        columns << 'Cert Hash'
      end

      # next draw up a table of transport entries
      tbl = Rex::Text::Table.new(
        'SortIndex' => 0, # sort by ID
        'Indent'    => 4,
        'Columns'   => columns)

      sorted_by_url.each_with_index do |t, i|
        entry = [i + 1, current_transport_url == t[:url] ? '*' : '', t[:url],
                  t[:comm_timeout], t[:retry_total], t[:retry_wait]]

        if opts[:verbose]
          entry << t[:ua]
          entry << t[:proxy_host]
          entry << t[:proxy_user]
          entry << t[:proxy_pass]
          entry << (t[:cert_hash] || '').unpack("H*")[0]
        end

        tbl << entry
      end

      print("\n" + tbl.to_s + "\n")
    when 'next'
      print_status('Changing to next transport ...')
      if client.core.transport_next
        print_good('Successfully changed to the next transport, killing current session.')
        client.shutdown_passive_dispatcher
        shell.stop
      else
        print_error('Failed to change transport, please check the parameters')
      end
    when 'prev'
      print_status('Changing to previous transport ...')
      if client.core.transport_prev
        print_good('Successfully changed to the previous transport, killing current session.')
        client.shutdown_passive_dispatcher
        shell.stop
      else
        print_error('Failed to change transport, please check the parameters')
      end
    when 'change'
      print_status('Changing to new transport ...')
      if client.core.transport_change(opts)
        print_good("Successfully added #{opts[:transport]} transport, killing current session.")
        client.shutdown_passive_dispatcher
        shell.stop
      else
        print_error('Failed to change transport, please check the parameters')
      end
    when 'add'
      print_status('Adding new transport ...')
      if client.core.transport_add(opts)
        print_good("Successfully added #{opts[:transport]} transport.")
      else
        print_error('Failed to add transport, please check the parameters')
      end
    when 'remove'
      if opts[:transport] && !opts[:transport].end_with?('_tcp') && opts[:uri].nil?
        print_error('HTTP/S transport specified without session URI')
        return
      end

      if !transport_index.zero? && @transport_map.has_key?(transport_index)
        # validate the URL
        url_to_delete = @transport_map[transport_index][:url]
        begin
          uri = URI.parse(url_to_delete)
          opts[:transport] = "reverse_#{uri.scheme}"
          opts[:lhost]     = uri.host
          opts[:lport]     = uri.port
          opts[:uri]       = uri.path[1..-2] if uri.scheme.include?('http')

        rescue URI::InvalidURIError
          print_error("Failed to parse URL: #{url_to_delete}")
          return
        end
      end

      print_status('Removing transport ...')
      if client.core.transport_remove(opts)
        print_good("Successfully removed #{opts[:transport]} transport.")
      else
        print_error('Failed to remove transport, please check the parameters')
      end
    end
  end

  @@migrate_opts = Rex::Parser::Arguments.new(
    '-P' => [true, 'PID to migrate to.'],
    '-N' => [true, 'Process name to migrate to.'],
    '-p' => [true, 'Writable path - Linux only (eg. /tmp).'],
    '-t' => [true, 'The number of seconds to wait for migration to finish (default: 60).'],
    '-h' => [false, 'Help menu.']
  )

  def cmd_migrate_help
    if client.platform == 'linux'
      print_line('Usage: migrate <<pid> | -P <pid> | -N <name>> [-p writable_path] [-t timeout]')
    else
      print_line('Usage: migrate <<pid> | -P <pid> | -N <name>> [-t timeout]')
    end
    print_line
    print_line('Migrates the server instance to another process.')
    print_line('NOTE: Any open channels or other dynamic state will be lost.')
    print_line
  end

  #
  # Migrates the server to the supplied process identifier.
  #
  # @param args [Array<String>] Commandline arguments, -h or a pid. On linux
  #   platforms a path for the unix domain socket used for IPC.
  # @return [void]
  def cmd_migrate(*args)
    if args.length == 0 || args.any? { |arg| %w(-h --pid --name).include? arg }
      cmd_migrate_help
      return true
    end

    pid = nil
    writable_dir = nil
    opts = {
      timeout: nil
    }

    @@migrate_opts.parse(args) do |opt, idx, val|
      case opt
      when '-t'
        opts[:timeout] = val.to_i
      when '-p'
        writable_dir = val
      when '-P'
        unless val =~ /^\d+$/
          print_error("Not a PID: #{val}")
          return
        end
        pid = val.to_i
      when '-N'
        if val.to_s.empty?
          print_error('No process name provided')
          return
        end
        # this will migrate to the first process with a matching name
        unless (process = client.sys.process.processes.find { |p| p['name'] == val })
          print_error("Could not find process name #{val}")
          return
        end
        pid = process['pid']
      end
    end

    # we cannot migrate to another process until loaded stdapi
    unless extensions.include?('stdapi')
      print_error('Stdapi extension must be loaded.')
      return
    end

    unless pid
      unless (pid = args.first)
        print_error('A process ID or name argument must be provided')
        return
      end
      unless pid =~ /^\d+$/
        print_error("Not a PID: #{pid}")
        return
      end
      pid = pid.to_i
    end

    begin
      server = client.sys.process.open
    rescue Rex::TimeoutError, ::Timeout::Error => e
      elog('Server Timeout', error: e)
    rescue RequestError => e
      elog('Request Error', error: e)
    end

    service = client.pfservice

    # If we have any open port forwards, we need to close them down
    # otherwise we'll end up with local listeners which aren't connected
    # to valid channels in the migrated meterpreter instance.
    existing_relays = []

    if service
      service.each_tcp_relay do |lhost, lport, rhost, rport, opts|
        next unless opts['MeterpreterRelay']
        if existing_relays.empty?
          print_status('Removing existing TCP relays...')
        end
        if (service.stop_tcp_relay(lport, lhost))
          print_status("Successfully stopped TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
          existing_relays << {
            :lport => lport,
            :opts => opts
          }
        else
          print_error("Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
          next
        end
      end
      unless existing_relays.empty?
        print_status("#{existing_relays.length} TCP relay(s) removed.")
      end
    end

    if pid == server.pid
      print_error("Process already running at PID #{pid}")
      return
    end

    server ? print_status("Migrating from #{server.pid} to #{pid}...") : print_status("Migrating to #{pid}")

    # Do this thang.
    client.core.migrate(pid, writable_dir, opts)

    print_status('Migration completed successfully.')

    # Update session info (we may have a new username)
    client.update_session_info

    unless existing_relays.empty?
      print_status('Recreating TCP relay(s)...')
      existing_relays.each do |r|
        client.pfservice.start_tcp_relay(r[:lport], r[:opts])
        print_status("Local TCP relay recreated: #{r[:opts]['LocalHost'] || '0.0.0.0'}:#{r[:lport]} <-> #{r[:opts]['PeerHost']}:#{r[:opts]['PeerPort']}")
      end
    end

  end

  def cmd_load_help
    print_line('Usage: load ext1 ext2 ext3 ...')
    print_line
    print_line('Loads a meterpreter extension module or modules.')
    print_line(@@load_opts.usage)
  end

  #
  # Loads one or more meterpreter extensions.
  #
  def cmd_load(*args)
    if args.length == 0
      args.unshift('-h')
    end

    @@load_opts.parse(args) { |opt, idx, val|
      case opt
      when '-l'
        exts = Set.new
        if extensions.include?('stdapi') && !client.sys.config.sysinfo['BuildTuple'].blank?
          # Use API to get list of extensions from the gem
          exts.merge(MetasploitPayloads::Mettle.available_extensions(client.sys.config.sysinfo['BuildTuple']))
        else
          exts.merge(client.binary_suffix.map { |suffix| MetasploitPayloads.list_meterpreter_extensions(suffix) }.flatten)
        end
        exts = exts.sort.uniq
        print(exts.to_a.join("\n") + "\n")

        return true
      when '-h'
        cmd_load_help
        return true
      end
    }

    # Load each of the modules
    args.each { |m|
      md = m.downcase

      # Temporary hack to pivot mimikatz over to kiwi until
      # everyone remembers to do it themselves
      if md == 'mimikatz'
        print_warning('The "mimikatz" extension has been replaced by "kiwi". Please use this in future.')
        md = 'kiwi'
      end

      modulenameprovided = md

      if client.binary_suffix and client.binary_suffix.size > 1
        client.binary_suffix.each { |s|
          if (md =~ /(.*)\.#{s}/ )
            md = $1
            break
          end
        }
      end

      if (extensions.include?(md))
        print_warning("The \"#{md}\" extension has already been loaded.")
        next
      end
      
      if extensions.include?('stdapi') && md.starts_with?('stdapi_')
        print_error("Full extension of stdapi has already been loaded.")
        next
      end

      loaded_stdapi_namespaces = extensions.select { |e| e.starts_with?('stdapi_')}

      if loaded_stdapi_namespaces.length > 0 && md == 'stdapi'
        print_error("Partial extension of stdapi has already been loaded.")
        next
      end

      client_load = (md == 'stdapi_audio' && loaded_stdapi_namespaces.select {|e| ['stdapi_webcam', 'stdapi_ui'].include?(e)}.any?)
                    (md == 'stdapi_sys'   && loaded_stdapi_namespaces.select {|e| ['stdapi_webcam', 'stdapi_ui'].include?(e)}.any?)
                    (md == 'stdapi_webcam' && loaded_stdapi_namespaces.select {|e| ['stdapi_ui'].include?(e)}.any?)

      print("Loading extension #{md}...")

      begin
        # Use the remote side, then load the client-side
        if (client_load || client.core.use(modulenameprovided) == true)
          add_extension_client(md)

          if md == 'stdapi' && (client.exploit_datastore && !client.exploit_datastore['AutoLoadStdapi'] && client.exploit_datastore['AutoSystemInfo'])
            client.load_session_info
          end
        end
      rescue => ex
        print_line
        log_error("Failed to load extension: #{ex.message}")
        elog(ex)
        if ex.kind_of?(ExtensionLoadError) && ex.name
          # MetasploitPayloads and MetasploitPayloads::Mettle do things completely differently, build an array of
          # suggestion keys (binary_suffixes and Mettle build-tuples)
          suggestion_keys = MetasploitPayloads.list_meterpreter_extension_suffixes(ex.name) + MetasploitPayloads::Mettle.available_platforms(ex.name)
          suggestion_map = {
            # Extension Suffixes
            'jar' => 'java',
            'php' => 'php',
            'py' => 'python',
            'x64.dll' => 'windows/x64',
            'x86.dll' => 'windows',
            # Mettle Platforms
            'aarch64-iphone-darwin' => 'apple_ios/aarch64',
            'aarch64-linux-musl' => 'linux/aarch64',
            'arm-iphone-darwin' => 'apple_ios/armle',
            'armv5b-linux-musleabi' => 'linux/armbe',
            'armv5l-linux-musleabi' => 'linux/armle',
            'i486-linux-musl' => 'linux/x86',
            'mips64-linux-muslsf' => 'linux/mips64',
            'mipsel-linux-muslsf' => 'linux/mipsle',
            'mips-linux-muslsf' => 'linux/mipsbe',
            'powerpc64le-linux-musl' => 'linux/ppc64le',
            'powerpc-e500v2-linux-musl' => 'linux/ppce500v2',
            'powerpc-linux-muslsf' => 'linux/ppc',
            's390x-linux-musl' => 'linux/zarch',
            'x86_64-apple-darwin' => 'osx/x64',
            'x86_64-linux-musl' => 'linux/x64',
          }
          suggestions = suggestion_map.select { |k,_v| suggestion_keys.include?(k) }.values
          unless suggestions.empty?
            log_error("The \"#{ex.name}\" extension is supported by the following Meterpreter payloads:")
            suggestions.each do |suggestion|
              log_error("  - #{suggestion}/meterpreter*")
            end
          end
        end

        next
      end

      print_line('Success.')
    }

    return true
  end

  def cmd_load_tabs(str, words)
    tabs = Set.new
    if extensions.include?('stdapi') && !client.sys.config.sysinfo['BuildTuple'].blank?
      tabs.merge(MetasploitPayloads::Mettle.available_extensions(client.sys.config.sysinfo['BuildTuple']))
    else
      tabs.merge(client.binary_suffix.map { |suffix| MetasploitPayloads.list_meterpreter_extensions(suffix) }.flatten)
    end
    tabs = tabs.sort.uniq
    return tabs.to_a
  end

  def cmd_micro_help
    print_line('Usage: micro alias <profile|object|command> [alias]')
    print_line('       micro load <manifest.yaml>')
    print_line('       micro load <name> <object.o>')
    print_line('       micro list')
    print_line('       micro has <command-id|command-name> [...]')
    print_line('       micro unload <name|handle>')
    print_line('       micro run <manifest-command> [arguments]')
    print_line
    print_line('Manages resident COFF objects that provide Meterpreter commands and channels.')
    return if @micro_manifest_commands.empty?

    print_line
    print_line('Manifest commands:')
    @micro_manifest_commands.each_value do |command|
      print_line("    #{command[:name].ljust(20)} #{command[:description]}")
    end
  end

  def cmd_micro(*args)
    operation = args.shift
    case operation
    when 'alias'
      return micro_alias_arguments(args)
    when 'load'
      return micro_load_arguments(args)
    when 'list'
      return micro_list if args.empty?
    when 'has'
      return micro_has_arguments(args) if args.any?
    when 'unload'
      return micro_unload_argument(args.first) if args.length == 1
    when 'run'
      return micro_invoke_manifest_command(args.shift, args) if @micro_manifest_commands.key?(args.first)
    end

    cmd_micro_help
    false
  end

  def cmd_micro_tabs(_str, words)
    return %w[alias load list has run unload] if words.length == 1
    return micro_alias_targets(words.last) if words.first == 'alias'
    return @micro_manifest_commands.keys.sort if words.first == 'run'
    return CommandMapper.get_command_names.select { |name| name.start_with?(words.last) } if words.first == 'has'

    []
  end

  def micro_alias_arguments(args)
    if args.empty?
      if @micro_command_aliases.empty?
        print_line('No microextension command aliases active.')
      else
        @micro_command_aliases.each { |alias_name, command_name| print_line("#{alias_name} -> micro run #{command_name}") }
      end
      return true
    end

    scope, alias_name = args
    unless args.length <= 2
      cmd_micro_help
      return false
    end

    candidates = if alias_name
                   command = @micro_manifest_commands[scope]
                   command ? [[alias_name, command[:name]]] : []
                 else
                   micro_alias_commands(scope).map { |command| [command[:name], command[:name]] }
                 end
    if candidates.empty?
      print_error("No loaded YAML command scope named #{scope}")
      return false
    end
    unless candidates.all? { |candidate_alias, _command_name| candidate_alias.match?(/\A[a-z][a-z0-9_]*\z/) }
      print_error('Microextension aliases must be lowercase command names')
      return false
    end

    conflict = candidates.find do |candidate_alias, command_name|
      @micro_command_aliases[candidate_alias] != command_name && shell.dispatcher_stack.any? { |dispatcher| dispatcher.commands.key?(candidate_alias) }
    end
    if conflict
      print_error("Cannot alias #{conflict.first}: a command with that name is already active")
      return false
    end

    candidates.each { |candidate_alias, command_name| @micro_command_aliases[candidate_alias] = command_name }
    micro_alias_dispatcher
    print_good("Aliased #{candidates.map(&:first).join(', ')}")
    true
  end

  def micro_alias_commands(scope)
    commands = @micro_manifest_commands.values.select { |command| command[:profile] == scope || command[:object] == scope }
    commands = [@micro_manifest_commands[scope]] if commands.empty? && @micro_manifest_commands.key?(scope)
    commands
  end

  def micro_alias_targets(prefix)
    targets = @micro_manifest_commands.values.flat_map { |command| [command[:profile], command[:object], command[:name]] }
    targets.uniq.grep(/\A#{Regexp.escape(prefix)}/).sort
  end

  def micro_alias_dispatcher_commands
    @micro_command_aliases.to_h do |alias_name, command_name|
      [alias_name, @micro_manifest_commands.fetch(command_name)[:description]]
    end
  end

  def micro_invoke_alias(alias_name, arguments)
    micro_invoke_manifest_command(@micro_command_aliases.fetch(alias_name), arguments)
  end

  def micro_alias_dispatcher
    return @micro_alias_dispatcher if @micro_alias_dispatcher && shell.dispatcher_stack.include?(@micro_alias_dispatcher)

    core_index = shell.dispatcher_stack.index(self) || shell.dispatcher_stack.length
    @micro_alias_dispatcher = Console::CommandDispatcher::MicroAlias.new(shell)
    shell.dispatcher_stack.insert(core_index, @micro_alias_dispatcher)
  end

  def micro_remove_alias_dispatcher
    shell.dispatcher_stack.delete(@micro_alias_dispatcher) if @micro_alias_dispatcher
    @micro_alias_dispatcher = nil
  end

  def micro_load_arguments(args)
    loaded = []
    objects = if args.length == 1
                micro_manifest_objects(args.first)
              elsif args.length == 2
                [{ name: args[0], path: ::File.expand_path(args[1]), commands: nil, channels: nil, adapter: nil, exposed_commands: [], ui_commands: [] }]
              else
                cmd_micro_help
                return false
              end

    objects.each do |object|
      unless ::File.file?(object[:path])
        raise Rex::RuntimeError, "Microextension object does not exist: #{object[:path]}"
      end

      image = ::File.binread(object[:path])
      object_architecture = micro_object_architecture(image)
      if object_architecture != micro_session_architecture
        raise Rex::RuntimeError, "#{object[:name]} is #{object_architecture || 'an unknown architecture'}, but this Meterpreter is #{micro_session_architecture}"
      end

      result = client.core.micro_load(object[:name], image)
      if (object[:commands] && object[:commands].sort != result[:commands].sort) || (object[:channels] && object[:channels].sort != result[:channels].sort)
        client.core.micro_unload(result[:handle])
        raise Rex::RuntimeError, "Manifest features do not match #{object[:name]}"
      end

      loaded << result.merge(object)
      print_good("Loaded #{object[:name]} as #{result[:handle]}: #{micro_extension_features(result)}")
    end

    loaded.each { |entry| micro_load_client_helper(entry) if entry[:helper] }

    loaded.reject { |entry| entry[:adapter].nil? }.group_by { |entry| entry[:adapter] }.each do |adapter, entries|
      ui_commands = entries.flat_map { |entry| entry[:ui_commands] }.select { |command| command[:delegate_adapter] }
      exposed_features = entries.each_with_object(Hash.new { |features, command| features[command] = [] }) do |entry, features|
        entry[:exposed_commands].each { |command| features[command] << { commands: entry[:commands], channels: entry[:channels] } }
      end
      micro_wire_commands(entries.flat_map { |entry| entry[:commands] }, entries.flat_map { |entry| entry[:channels] }, adapter, entries.flat_map { |entry| entry[:exposed_commands] }.uniq, ui_commands, ui_commands.map { |command| command[:delegate_command] }, exposed_features)
    end
    ui_commands = loaded.flat_map { |entry| entry[:ui_commands] }.reject { |command| command[:delegate_adapter] }
    micro_wire_commands([], [], nil, [], ui_commands) unless ui_commands.empty?
    true
  rescue StandardError => error
    loaded.reverse_each do |entry|
      removed = client.core.micro_unload(entry[:handle])
      micro_unwire_commands(removed)
    rescue StandardError => rollback_error
      elog(rollback_error)
    end
    print_error("Microextension load failed: #{error.message}")
    false
  end

  def micro_manifest_objects(path)
    expanded_path = ::File.expand_path(path)
    raise Rex::RuntimeError, "Microextension manifest does not exist: #{expanded_path}" unless ::File.file?(expanded_path)

    manifest = YAML.safe_load(::File.read(expanded_path), permitted_classes: [], aliases: false)
    unless manifest.is_a?(Hash) && manifest['schema'] == 'meterpreter-micro/v1' && manifest['objects'].is_a?(Array)
      raise Rex::RuntimeError, 'Expected a meterpreter-micro/v1 manifest with an objects list'
    end
    profile = manifest['profile']
    unless profile.is_a?(String) && profile.match?(/\A[a-z][a-z0-9_-]*\z/)
      raise Rex::RuntimeError, 'The manifest requires a valid profile name'
    end
    unless manifest['platform'] == 'windows'
      raise Rex::RuntimeError, 'This implementation only supports Windows microextensions'
    end

    architectures = Array(manifest['architecture'])
    unless architectures.all? { |architecture| architecture.is_a?(String) } && architectures.include?(micro_session_architecture)
      raise Rex::RuntimeError, "The manifest does not support this Meterpreter architecture (#{micro_session_architecture})"
    end

    manifest['objects'].map do |object|
      name = object['name'] if object.is_a?(Hash)
      files = object['file'] if object.is_a?(Hash)
      file = files[micro_session_architecture] if files.is_a?(Hash)
      file ||= files if files.is_a?(String)
      commands = object['commands'] if object.is_a?(Hash)
      channels = object['channels'] if object.is_a?(Hash)
      channels ||= []
      unless name.is_a?(String) && !name.empty? && file.is_a?(String) && commands.is_a?(Array)
        raise Rex::RuntimeError, 'Each manifest object requires name, file, and commands'
      end

      command_ids = commands.map { |command| command['id'] if command.is_a?(Hash) }
      raise Rex::RuntimeError, "Invalid command list for #{name}" unless command_ids.all? { |command_id| command_id.is_a?(Integer) }
      unless channels.is_a?(Array) && channels.all? { |type| type.is_a?(String) && !type.empty? }
        raise Rex::RuntimeError, "Invalid channel provider list for #{name}"
      end

      client_definition = object['client']
      adapter = client_definition['adapter'] if client_definition.is_a?(Hash)
      exposed_commands = client_definition['expose'] if client_definition.is_a?(Hash)
      helper_definition = client_definition['helper'] if client_definition.is_a?(Hash)
      helper = micro_manifest_client_helper(helper_definition, expanded_path, name)
      exposed_commands ||= []
      unless adapter.nil? || (adapter.is_a?(String) && !adapter.empty?)
        raise Rex::RuntimeError, "Invalid client adapter for #{name}"
      end
      unless exposed_commands.is_a?(Array) && exposed_commands.all? { |command| command.is_a?(String) && !command.empty? }
        raise Rex::RuntimeError, "Invalid exposed command list for #{name}"
      end
      if adapter.nil? && !exposed_commands.empty?
        raise Rex::RuntimeError, "Exposed commands for #{name} require a client adapter"
      end
      if helper && (adapter || exposed_commands.any?)
        raise Rex::RuntimeError, "Ruby helper for #{name} cannot be combined with a built-in client adapter"
      end

      ui_commands = micro_manifest_ui_commands(object['ui'], profile, name, command_ids, adapter, channels)
      { name: name, profile: profile, path: ::File.expand_path(file, ::File.dirname(expanded_path)), commands: command_ids, channels: channels, adapter: adapter, exposed_commands: exposed_commands, helper: helper, ui_commands: ui_commands }
    end
  rescue Psych::SyntaxError => error
    raise Rex::RuntimeError, "Invalid microextension manifest: #{error.message}"
  end

  def micro_manifest_client_helper(helper, manifest_path, object_name)
    return nil if helper.nil?
    unless helper.is_a?(Hash) && (helper.keys - %w[alias file source]).empty?
      raise Rex::RuntimeError, "Invalid Ruby helper for #{object_name}"
    end

    file = helper['file']
    embedded_source = helper['source']
    unless [file, embedded_source].count { |value| value.is_a?(String) && !value.empty? } == 1
      raise Rex::RuntimeError, "Ruby helper for #{object_name} requires exactly one file or source"
    end

    client_alias = helper['alias']
    unless client_alias.nil? || (client_alias.is_a?(String) && client_alias.match?(/\A[a-z][a-z0-9_]*\z/))
      raise Rex::RuntimeError, "Invalid Ruby helper alias for #{object_name}"
    end

    {
      path: file && ::File.expand_path(file, ::File.dirname(manifest_path)),
      source: embedded_source,
      alias: client_alias
    }
  end

  def micro_load_client_helper(entry)
    definition = entry[:helper]
    source_path = definition[:path]
    if source_path && !::File.file?(source_path)
      raise Rex::RuntimeError, "Ruby helper does not exist: #{source_path}"
    end

    source = definition[:source] || ::File.binread(source_path)
    raise Rex::RuntimeError, "Ruby helper for #{entry[:name]} exceeds 1 MiB" if source.bytesize > 1_048_576

    helper_class = Rex::Post::Meterpreter::MicroHelper.compile(source, source_path || "#{entry[:profile]}:#{entry[:name]}:inline")
    command_definitions = helper_class.command_definitions || {}
    command_definitions.each do |name, command|
      unless name.match?(/\A[a-z][a-z0-9_]*\z/) && !%w[has help list load run unload].include?(name) && command[:description].is_a?(String)
        raise Rex::RuntimeError, "Invalid Ruby helper command for #{entry[:name]}: #{name}"
      end
      raise Rex::RuntimeError, "Helper command #{name} is already loaded" if @micro_manifest_commands.key?(name)
    end
    if command_definitions.empty? && definition[:alias].nil?
      raise Rex::RuntimeError, "Ruby helper for #{entry[:name]} defines no commands or client alias"
    end
    if definition[:alias] && client.respond_to?(definition[:alias], true)
      raise Rex::RuntimeError, "Client alias #{definition[:alias]} is already active"
    end

    helper = helper_class.new(shell, profile: entry[:profile], object_name: entry[:name], channel_types: entry[:channels])
    key = "#{entry[:profile]}:#{entry[:name]}"
    client.register_extension_alias(definition[:alias], helper) if definition[:alias]
    @micro_helpers[key] = {
      instance: helper,
      client_alias: definition[:alias],
      command_ids: entry[:commands],
      channel_types: entry[:channels]
    }
    command_definitions.each do |name, command|
      @micro_manifest_commands[name] = {
        name: name,
        profile: entry[:profile],
        object: entry[:name],
        description: command[:description],
        helper_key: key
      }
    end
  rescue SyntaxError, LoadError => error
    raise Rex::RuntimeError, "Unable to load Ruby helper for #{entry[:name]}: #{error.message}"
  rescue StandardError
    helper&.cleanup
    client.deregister_extension_alias(definition[:alias]) if definition[:alias] && helper
    raise
  end

  def micro_session_architecture
    client.arch.to_s
  end

  def micro_object_architecture(image)
    { 0x014c => 'x86', 0x8664 => 'x64' }[image.unpack1('v')]
  end

  def micro_has_arguments(args)
    commands = args.map do |argument|
      command_id = argument.match?(/\A\d+\z/) ? argument.to_i : CommandMapper.get_command_id(argument)
      command_id ||= @micro_manifest_commands.dig(argument, :command_id)
      unless command_id
        print_error("Unknown Meterpreter command: #{argument}")
        return false
      end

      [argument, command_id]
    end

    availability = client.core.micro_has_commands(commands.map(&:last))
    commands.each do |argument, command_id|
      state = availability[command_id] ? 'Present' : 'Absent'
      print_line("#{state}: #{argument} (#{command_id})")
    end
    true
  end

  def micro_list
    entries = client.core.micro_extensions
    if entries.empty?
      print_line('No microextensions loaded.')
    else
      entries.each do |entry|
        print_line("#{entry[:handle]}: #{entry[:name]} (ABI #{entry[:abi]}) - #{micro_extension_features(entry)}")
      end
    end
    true
  end

  def micro_unload_argument(identifier)
    handle = identifier.match?(/\A\d+\z/) ? identifier.to_i : identifier
    removed = client.core.micro_unload(handle)
    micro_unwire_commands(removed)
    print_good("Unloaded #{identifier}: #{micro_extension_features(removed)}")
    true
  rescue StandardError => error
    print_error("Microextension unload failed: #{error.message}")
    false
  end

  def micro_command_names(command_ids)
    command_ids.map { |command_id| CommandMapper.get_command_name(command_id) || command_id }.join(', ')
  end

  def micro_extension_features(entry)
    features = micro_command_names(entry[:commands])
    features = 'no packet commands' if features.empty?
    channels = entry[:channels]
    channels.empty? ? features : "#{features}; channels: #{channels.join(', ')}"
  end

  def micro_manifest_ui_commands(ui, profile, object_name, command_ids, adapter, channel_types)
    return [] if ui.nil?

    definitions = ui['commands'] if ui.is_a?(Hash)
    unless definitions.is_a?(Array)
      raise Rex::RuntimeError, "Invalid YAML UI for #{object_name}"
    end

    definitions.map do |definition|
      unless definition.is_a?(Hash) && definition['name'].is_a?(String) && definition['name'].match?(/\A[a-z][a-z0-9_]*\z/) && !%w[has help list load run unload].include?(definition['name']) && definition['description'].is_a?(String)
        raise Rex::RuntimeError, "Invalid YAML UI command for #{object_name}"
      end

      delegate = definition['delegate']
      if delegate
        unless delegate.is_a?(Hash) && delegate['adapter'] == adapter && delegate['command'].is_a?(String) && !delegate['command'].empty? && channel_types.any?
          raise Rex::RuntimeError, "Invalid YAML UI delegate for #{definition['name']}"
        end
        next({
          name: definition['name'],
          profile: profile,
          object: object_name,
          description: definition['description'],
          delegate_adapter: adapter,
          delegate_command: delegate['command'],
          channel_types: channel_types
        })
      end

      request = definition['request']
      response = definition['response']
      output = definition['output']
      arguments = request['arguments'] if request.is_a?(Hash)
      fields = response['fields'] if response.is_a?(Hash)
      rows = response['rows'] if response.is_a?(Hash)
      command_id = request['command'] if request.is_a?(Hash)
      arguments ||= []
      fields ||= []
      rows ||= []
      unless command_ids.include?(command_id) && micro_ui_tlvs_valid?(arguments, arguments: true) && micro_ui_tlvs_valid?(fields) && micro_ui_rows_valid?(rows) && micro_ui_output_valid?(output, fields, rows)
        raise Rex::RuntimeError, "Invalid YAML UI definition for #{definition['name']}"
      end

      {
        name: definition['name'],
        profile: profile,
        object: object_name,
        description: definition['description'],
        command_id: command_id,
        arguments: micro_ui_tlvs(arguments),
        fields: micro_ui_tlvs(fields),
        rows: micro_ui_rows(rows),
        output: micro_ui_output(output),
        channel_types: []
      }
    end
  end

  def micro_ui_tlvs_valid?(definitions, arguments: false)
    definitions.is_a?(Array) && definitions.all? do |definition|
      definition.is_a?(Hash) && definition['name'].is_a?(String) && definition['name'].match?(/\A[a-z][a-z0-9_]*\z/) && (arguments ? %w[bool qword string uint] : %w[bool qword raw string uint]).include?(definition['type']) && definition['tlv'].is_a?(Integer) && definition['tlv'].between?(0, 0xffff) && (!arguments || micro_ui_argument_valid?(definition))
    end
  end

  def micro_ui_argument_valid?(definition)
    required = definition.fetch('required', true)
    (required == true || required == false) && (required || definition.key?('default'))
  end

  def micro_ui_rows_valid?(rows)
    rows.is_a?(Array) && rows.all? do |definition|
      next false unless definition.is_a?(Hash)
      next micro_ui_tlvs_valid?([definition]) unless %w[group raw].include?(definition['type'])

      name_and_type_valid = micro_ui_tlvs_valid?([{ 'name' => definition['name'], 'type' => 'string', 'tlv' => definition['tlv'] }])
      if definition['type'] == 'group'
        next name_and_type_valid && micro_ui_tlvs_valid?(definition['fields'])
      end

      name_and_type_valid && definition['extract'].is_a?(Array) && definition['extract'].all? do |extract|
        extract.is_a?(Hash) && extract['name'].is_a?(String) && extract['name'].match?(/\A[a-z][a-z0-9_]*\z/) && %w[qword uint].include?(extract['type']) && extract['offset'].is_a?(Integer) && extract['offset'] >= 0
      end
    end
  end

  def micro_ui_output_valid?(output, fields, rows)
    return false unless output.is_a?(Hash)

    if rows.empty?
      formats = output['lines'] || [output['format']]
      return micro_ui_tlvs_valid?(fields) && formats.is_a?(Array) && formats.all? { |format| format.is_a?(String) }
    end

    columns = output['columns']
    output['type'] == 'table' && output['header'].is_a?(String) && columns.is_a?(Array) && columns.all? do |column|
      column.is_a?(Hash) && column['label'].is_a?(String) && column['name'].is_a?(String) && %w[octal raw unix_time].include?(column.fetch('display', 'raw'))
    end
  end

  def micro_ui_tlvs(definitions)
    definitions.map do |definition|
      { name: definition['name'], type: definition['type'], tlv: micro_ui_tlv_type(definition['type'], definition['tlv']), required: definition.fetch('required', true), default: definition['default'] }
    end
  end

  def micro_ui_rows(definitions)
    definitions.map do |definition|
      if definition['type'] == 'raw'
        { name: definition['name'], tlv: TLV_META_TYPE_COMPLEX | definition['tlv'], fields: [], extract: definition['extract'].map { |extract| extract.transform_keys(&:to_sym) } }
      elsif definition['type'] == 'group'
        { name: definition['name'], tlv: TLV_META_TYPE_GROUP | definition['tlv'], fields: micro_ui_tlvs(definition['fields']), extract: [] }
      else
        { name: definition['name'], tlv: micro_ui_tlv_type(definition['type'], definition['tlv']), fields: [], extract: [] }
      end
    end
  end

  def micro_ui_output(output)
    return { type: :lines, formats: output['lines'] || [output['format']] } unless output['type'] == 'table'

    { type: :table, header: output['header'], columns: output['columns'].map { |column| column.transform_keys(&:to_sym) } }
  end

  def micro_ui_tlv_type(type, number)
    {
      'bool' => TLV_META_TYPE_BOOL,
      'qword' => TLV_META_TYPE_QWORD,
      'raw' => TLV_META_TYPE_RAW,
      'string' => TLV_META_TYPE_STRING,
      'uint' => TLV_META_TYPE_UINT
    }.fetch(type) | number
  end

  def micro_wire_commands(command_ids, channel_types, adapter, exposed_commands, ui_commands, hidden_commands = [], exposed_features = {})
    duplicate_command = ui_commands.find { |command| @micro_manifest_commands.key?(command[:name]) }
    raise Rex::RuntimeError, "YAML UI command #{duplicate_command[:name]} is already loaded" if duplicate_command

    micro_refresh_commands
    if adapter
      raise Rex::RuntimeError, "Client adapter #{adapter} is already active" if extensions.include?(adapter) || @micro_dispatchers.key?(adapter)

      client.add_extension(adapter, [])
      dispatchers = []
      unless exposed_commands.empty?
        previous_dispatchers = shell.dispatcher_stack.dup
        dispatcher = add_extension_client(adapter)
        raise Rex::RuntimeError, "Failed to initialize #{adapter}" unless dispatcher

        dispatchers = shell.dispatcher_stack.reject { |entry| previous_dispatchers.include?(entry) }
        available_commands = dispatchers.flat_map { |entry| entry.commands.keys }
        missing_commands = requested_commands - available_commands
        unless missing_commands.empty?
          dispatchers.each { |entry| shell.dispatcher_stack.delete(entry) }
          extensions.delete(adapter)
          client.deregister_extension(adapter)
          raise Rex::RuntimeError, "Client adapter #{adapter} does not provide: #{missing_commands.join(', ')}"
        end

        dispatchers.each { |entry| entry.micro_ui_commands = exposed_commands }
        dispatchers.each { |entry| shell.dispatcher_stack.delete(entry) } if exposed_commands.empty?
      end

      @micro_dispatchers[adapter] = { command_ids: command_ids, channel_types: channel_types, dispatchers: dispatchers, exposed_features: exposed_features }
    end

    ui_commands.each { |command| @micro_manifest_commands[command[:name]] = command }
  end

  def micro_invoke_manifest_command(name, arguments)
    command = @micro_manifest_commands.fetch(name)
    if command[:helper_key]
      begin
        return @micro_helpers.fetch(command[:helper_key])[:instance].invoke_command(name, arguments)
      rescue StandardError => error
        print_error("Microextension helper failed: #{error.message}")
        return false
      end
    end
    if command[:delegate_command]
      dispatchers = @micro_dispatchers.dig(command[:delegate_adapter], :dispatchers) || []
      dispatcher = dispatchers.find { |entry| entry.respond_to?("cmd_#{command[:delegate_command]}", true) }
      raise Rex::RuntimeError, "Client delegate #{command[:delegate_adapter]}.#{command[:delegate_command]} is not active" unless dispatcher

      dispatcher.__send__("cmd_#{command[:delegate_command]}", *arguments)
      return true
    end

    required_count = command[:arguments].count { |argument| argument[:required] }
    if arguments.length < required_count || arguments.length > command[:arguments].length
      usage = command[:arguments].map { |argument| argument[:required] ? "<#{argument[:name]}>" : "[#{argument[:name]}]" }.join(' ')
      print_error("Usage: micro run #{name} #{usage}".rstrip)
      return false
    end

    request = Packet.create_request(command[:command_id])
    command[:arguments].each_with_index do |argument, index|
      value = arguments[index] || argument[:default]
      request.add_tlv(argument[:tlv], micro_ui_value(argument[:type], value))
    end
    response = client.send_request(request)
    micro_render_manifest_response(command, response)
    true
  rescue ArgumentError, KeyError, RangeError, RequestError, Rex::RuntimeError => error
    print_error("Microextension command failed: #{error.message}")
    false
  end

  def micro_render_manifest_response(command, response)
    if command[:output][:type] == :lines
      values = command[:fields].to_h { |field| [field[:name].to_sym, micro_ui_response_value(response.get_tlv_value(field[:tlv]), field[:type])] }
      command[:output][:formats].each { |format| print_line(format % values) }
      return
    end

    row_values = command[:rows].to_h { |row| [row, response.get_tlvs(row[:tlv])] }
    row_count = row_values.values.map(&:length).max || 0
    table = Rex::Text::Table.new('Header' => command[:output][:header], 'Columns' => command[:output][:columns].map { |column| column[:label] })
    row_count.times do |index|
      values = micro_ui_row(row_values, index)
      table << command[:output][:columns].map { |column| micro_ui_display(values[column[:name]], column[:display]) }
    end
    print_line(table.to_s)
  end

  def micro_ui_row(row_values, index)
    row_values.each_with_object({}) do |(row, values), result|
      tlv = values[index]
      if row[:fields].any?
        row[:fields].each { |field| result[field[:name]] = micro_ui_response_value(tlv&.get_tlv_value(field[:tlv]), field[:type]) }
      elsif row[:extract].empty?
        result[row[:name]] = tlv&.value
      else
        row[:extract].each { |extract| result[extract[:name]] = micro_ui_extract(tlv&.value, extract) }
      end
    end
  end

  def micro_ui_extract(value, extract)
    size = extract[:type] == 'uint' ? 4 : 8
    raise ArgumentError, "Invalid #{extract[:name]} field" unless value.is_a?(String) && value.bytesize >= extract[:offset] + size

    value.unpack1(extract[:type] == 'uint' ? 'V' : 'Q<', offset: extract[:offset])
  end

  def micro_ui_response_value(value, type)
    type == 'raw' && value.is_a?(String) ? value.unpack1('H*') : value
  end

  def micro_ui_display(value, display)
    return format('%06o', value) if display == 'octal'
    return ::Time.at(value).strftime('%Y-%m-%d %H:%M:%S') if display == 'unix_time'

    value
  end

  def micro_ui_value(type, value)
    return value if type == 'string'
    return true if type == 'bool' && value == 'true'
    return false if type == 'bool' && value == 'false'

    integer = Integer(value, 0)
    return integer if type == 'uint' && integer.between?(0, 0xffffffff)
    return integer if type == 'qword' && integer.between?(0, 0xffffffffffffffff)

    raise ArgumentError, "Invalid #{type} value: #{value}"
  end

  def micro_unwire_commands(_features)
    micro_refresh_commands
    @micro_helpers.delete_if do |_key, wiring|
      next false if (wiring[:command_ids] - client.micro_commands).empty? && (wiring[:channel_types] - client.micro_channels).empty?

      begin
        wiring[:instance].cleanup
      rescue StandardError => error
        elog(error)
      end
      client.deregister_extension_alias(wiring[:client_alias]) if wiring[:client_alias]
      true
    end
    @micro_manifest_commands.delete_if do |_name, command|
      if command[:helper_key]
        !@micro_helpers.key?(command[:helper_key])
      elsif command[:command_id]
        !client.micro_commands.include?(command[:command_id])
      else
        (command[:channel_types] - client.micro_channels).any?
      end
    end
    @micro_command_aliases.delete_if { |_alias_name, command_name| !@micro_manifest_commands.key?(command_name) }
    micro_remove_alias_dispatcher if @micro_command_aliases.empty?
    @micro_dispatchers.delete_if do |adapter, wiring|
      if (wiring[:command_ids] & client.micro_commands).any? || (wiring[:channel_types] & client.micro_channels).any?
        exposed_commands = wiring[:exposed_features].select do |_command, requirements|
          requirements.any? { |requirement| (requirement[:commands] - client.micro_commands).empty? && (requirement[:channels] - client.micro_channels).empty? }
        end.keys
        wiring[:dispatchers].each { |dispatcher| dispatcher.micro_ui_commands = exposed_commands }
        next false
      end

      extensions.delete(adapter)
      wiring[:dispatchers].each { |dispatcher| shell.dispatcher_stack.delete(dispatcher) }
      client.deregister_extension(adapter)
      true
    end
  end

  def micro_refresh_commands
    remote_extensions = client.core.micro_extensions
    remote_commands = remote_extensions.flat_map { |extension| extension[:commands] }.uniq
    remote_channels = remote_extensions.flat_map { |extension| extension[:channels] }.uniq
    removed_commands = client.micro_commands - remote_commands
    new_commands = remote_commands - client.micro_commands

    removed_commands.each { |command_id| client.commands.delete(command_id) }
    client.commands.concat(new_commands)
    client.micro_commands.replace(remote_commands)
    client.micro_channels.replace(remote_channels)
  end

  def cmd_use(*args)
    #print_error("Warning: The 'use' command is deprecated in favor of 'load'")
    cmd_load(*args)
  end
  alias cmd_use_help cmd_load_help
  alias cmd_use_tabs cmd_load_tabs

  def cmd_read_help
    print_line('Usage: read <channel_id> [length]')
    print_line
    print_line('Reads data from the supplied channel.')
    print_line
  end

  #
  # Reads data from a channel.
  #
  def cmd_read(*args)
    if args.empty? || args.include?('-h')
      cmd_read_help
      return true
    end

    cid     = args[0].to_i
    length  = (args.length >= 2) ? args[1].to_i : 16384
    channel = client.find_channel(cid)

    unless channel
      print_error("Channel #{cid} is not valid.")
      return true
    end

    data = channel.read(length)

    if data && data.length
      print("Read #{data.length} bytes from #{cid}:\n\n#{data}\n")
    else
      print_error('No data was returned.')
    end

    return true
  end

  alias cmd_read_tabs cmd_close_tabs

  def cmd_run_help
    print_line('Usage: run <script> [arguments]')
    print_line
    print_line('Executes a ruby script or Metasploit Post module in the context of the')
    print_line('meterpreter session.  Post modules can take arguments in var=val format.')
    print_line('Example: run post/foo/bar BAZ=abcd')
    print_line
  end

  #
  # Executes a script in the context of the meterpreter session.
  #
  def cmd_run(*args)
    if args.empty? || args.first == '-h'
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

        opts = ''
        if reloaded_mod.is_a?(Msf::Exploit)
          # set the payload as one of the first options, allowing it to be overridden by the user
          opts << "PAYLOAD=#{client.via_payload.delete_prefix('payload/')}," if client.via_payload
        end

        opts  << (args + [ "SESSION=#{client.sid}" ]).join(',')
        result = reloaded_mod.run_simple({
          #'RunAsJob' => true,
          'LocalInput'  => shell.input,
          'LocalOutput' => shell.output,
          'OptionStr'   => opts
        })

        print_status("Session #{result.sid} created in the background.") if result.is_a?(Msf::Session)
      else
        # the rest of the arguments get passed in through the binding
        client.execute_script(script_name, args)
      end
    rescue => e
      print_error("Error in script: #{script_name}")
      elog("Error in script: #{script_name}", error: e)
    end
  end

  def cmd_run_tabs(str, words)
    tabs = []
    unless words[1] && words[1].match(/^\//)
      begin
        tabs += tab_complete_modules(str, words) if msf_loaded?
        [
          ::Msf::Sessions::Meterpreter.script_base,
          ::Msf::Sessions::Meterpreter.user_script_base
        ].each do |dir|
          next if not ::File.exist? dir
          tabs += ::Dir.new(dir).find_all { |e|
            path = dir + ::File::SEPARATOR + e
            ::File.file?(path) and ::File.readable?(path)
          }
        end
      rescue Exception
      end
    end

    tabs.map { |e| e.sub(/\.rb$/, '') }
  end


  #
  # Executes a script in the context of the meterpreter session in the background
  #
  def cmd_bgrun(*args)
    if args.empty? || args.first == '-h'
      print_line('Usage: bgrun <script> [arguments]')
      print_line
      print_line('Executes a ruby script in the context of the meterpreter session.')
      print_line

      return true
    end

    jid = self.bgjob_id
    self.bgjob_id += 1

    # Get the script name
    self.bgjobs[jid] = Rex::ThreadFactory.spawn("MeterpreterBGRun(#{args[0]})-#{jid}", false, jid, args) do |myjid,xargs|
      ::Thread.current[:args] = xargs.dup
      begin
        # the rest of the arguments get passed in through the binding
        script_name = args.shift
        client.execute_script(script_name, args)
      rescue ::Exception => e
        print_error("Error in script: #{script_name}")
        elog("Error in script: #{script_name}", error: e)
      end
      self.bgjobs[myjid] = nil
      print_status("Background script with Job ID #{myjid} has completed (#{::Thread.current[:args].inspect})")
    end

    print_status("Executed Meterpreter with Job ID #{jid}")
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
    if args.empty? || args.include?('-h')
      print_line('Usage: bgkill [id]')
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
    print_line('Usage: info <module>')
    print_line
    print_line('Prints information about a post-exploitation module')
    print_line
  end

  #
  # Show info for a given Post module.
  #
  # See also +cmd_info+ in lib/msf/ui/console/command_dispatcher/core.rb
  #
  def cmd_info(*args)
    return unless msf_loaded?

    if args.length != 1 or args.include?('-h')
      cmd_info_help
      return
    end

    module_name = args.shift
    mod = client.framework.modules.create(module_name);

    if mod.nil?
      print_error("Invalid module: #{module_name}")
    end

    if (mod)
      print_line(::Msf::Serializer::ReadableText.dump_module(mod))
      mod_opt = ::Msf::Serializer::ReadableText.dump_options(mod, '   ')
      print_line("\nModule options (#{mod.fullname}):\n\n#{mod_opt}") if (mod_opt and mod_opt.length > 0)
    end
  end

  def cmd_info_tabs(str, words)
    tab_complete_modules(str, words) if msf_loaded?
  end

  #
  # Writes data to a channel.
  #
  @@write_opts = Rex::Parser::Arguments.new(
    '-f' => [true, 'Write the contents of a file on disk'],
    '-h' => [false, 'Help menu.'])

  def cmd_write_help
    print_line('Usage: write [options] channel_id')
    print_line
    print_line('Writes data to the supplied channel.')
    print_line(@@write_opts.usage)
  end

  def cmd_write_tabs(str, words)
    return tab_complete_filenames(str, words) if words[-1] == '-f'
    tab_complete_channels
  end

  def cmd_write(*args)
    if args.length == 0 || args.include?("-h")
      cmd_write_help
      return
    end

    src_file = nil
    cid      = nil

    @@write_opts.parse(args) { |opt, idx, val|
      case opt
      when "-f"
        src_file = val
      else
        cid = val.to_i
      end
    }

    # Find the channel associated with this cid, assuming the cid is valid.
    unless cid && channel = client.find_channel(cid)
      print_error('Invalid channel identifier specified.')
      return true
    end

    # If they supplied a source file, read in its contents and write it to
    # the channel
    if src_file
      begin
        data = ''

        ::File.open(src_file, 'rb') { |f|
          data = f.read(f.stat.size)
        }

      rescue Errno::ENOENT
        print_error("Invalid source file specified: #{src_file}")
        return true
      end

      if data && data.length > 0
        channel.write(data)
        print_status("Wrote #{data.length} bytes to channel #{cid}.")
      else
        print_error("No data to send from file #{src_file}")
        return true
      end
    # Otherwise, read from the input descriptor until we're good to go.
    else
      print_line('Enter data followed by a "." on an empty line:')
      print_line
      print_line

      data = ''

      # Keep truckin'
      while s = shell.input.gets
        break if s =~ /^\.\r?\n?$/
        data += s
      end

      if !data || data.length == 0
        print_error('No data to send.')
      else
        channel.write(data)
        print_status("Wrote #{data.length} bytes to channel #{cid}.")
      end
    end

    return true
  end

  def cmd_enable_unicode_encoding
    client.encode_unicode = true
    print_status('Unicode encoding is enabled')
  end

  def cmd_disable_unicode_encoding
    client.encode_unicode = false
    print_status('Unicode encoding is disabled')
  end

  @@client_extension_search_paths = [::File.join(Rex::Root, 'post', 'meterpreter', 'ui', 'console', 'command_dispatcher')]

  def self.add_client_extension_search_path(path)
    @@client_extension_search_paths << path unless @@client_extension_search_paths.include?(path)
  end

  def self.client_extension_search_paths
    @@client_extension_search_paths
  end

  def unknown_command(cmd, line)
    status = super

    if status.nil?
      # Check to see if we can find this command in another extension. This relies on the core extension being the last
      # in the dispatcher stack which it should be since it's the first loaded.
      Rex::Post::Meterpreter::ExtensionMapper.get_extension_names.select{ | ext_name | !ext_name.starts_with?('stdapi_')}.each do |ext_name|
        next if extensions.include?(ext_name)
        ext_klass = get_extension_client_class(ext_name)
        next if ext_klass.nil?

        if ext_klass.has_command?(cmd)
          print_error("The \"#{cmd}\" command requires the \"#{ext_name}\" extension to be loaded (run: `load #{ext_name}`)") if ext_name != "stdapi"
          print_error("The \"#{cmd}\" command requires the stdapi extension to be loaded or the relative subcomponent (run: `load stdapi` or `load stdapi_audio/_fs/_net/_sys/_railgun/_ui/_webcam`)") if ext_name == "stdapi"
          return :handled
        end
      end
    end

    status
  end

protected

  attr_accessor :extensions # :nodoc:
  attr_accessor :bgjobs, :bgjob_id # :nodoc:

  CommDispatcher = Console::CommandDispatcher

  #
  # Loads the client extension specified in mod
  #
  def add_extension_client(mod)
    klass = get_extension_client_class(mod)

    if klass.nil?
      print_error("Failed to load client portion of #{mod}.")
      return false
    end

    # Enstack the dispatcher
    dispatcher = self.shell.enstack_dispatcher(klass)

    # Insert the module into the list of extensions
    self.extensions << mod

    dispatcher
  end

  def get_extension_client_class(mod)
    self.class.client_extension_search_paths.each do |path|
      path = ::File.join(path, "#{mod}.rb")
      klass = CommDispatcher.check_hash(path)
      return klass unless klass.nil?

      old = CommDispatcher.constants
      next unless ::File.exist? path

      return nil unless require(path)

      new  = CommDispatcher.constants
      diff = new - old

      next if (diff.empty?)

      klass = CommDispatcher.const_get(diff[0])

      CommDispatcher.set_hash(path, klass)
      return klass
    end
  end

  def tab_complete_modules(str, words)
    tabs = []
    module_metadata = Msf::Modules::Metadata::Cache.instance.get_metadata

    tabs += module_metadata.filter_map do |m|
      if m.type == 'post' || (m.type == 'exploit' && m.ref_name.match(%r{(multi|#{Regexp.escape(client.platform)})/local/}))
        "#{m.type}/#{m.ref_name}"
      end
    end

    client.framework.modules.post.module_refnames.each do | name |
      tabs << 'post/' + name
    end
    client.framework.modules.module_names('exploit').
      grep(/(multi|#{Regexp.escape(client.platform)})\/local\//).each do |name|
      tabs << 'exploit/' + name
    end

    tabs.uniq.sort
  end

  def tab_complete_channels
    client.channels.keys.map { |k| k.to_s }
  end

end

end
end
end
end
