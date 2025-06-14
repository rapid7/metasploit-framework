# -*- coding: binary -*-
require 'set'
require 'rex/post/meterpreter'
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

      print("Loading extension #{md}...")

      begin
        # Use the remote side, then load the client-side
        if (client.core.use(modulenameprovided) == true)
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
        result = reloaded_mod.run_simple(
          #'RunAsJob' => true,
          'LocalInput'  => shell.input,
          'LocalOutput' => shell.output,
          'OptionStr'   => opts
        )

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
      Rex::Post::Meterpreter::ExtensionMapper.get_extension_names.each do |ext_name|
        next if extensions.include?(ext_name)
        ext_klass = get_extension_client_class(ext_name)
        next if ext_klass.nil?

        if ext_klass.has_command?(cmd)
          print_error("The \"#{cmd}\" command requires the \"#{ext_name}\" extension to be loaded (run: `load #{ext_name}`)")
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
    self.shell.enstack_dispatcher(klass)

    # Insert the module into the list of extensions
    self.extensions << mod
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
