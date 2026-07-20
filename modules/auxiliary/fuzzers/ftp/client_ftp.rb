##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# Fuzzer written by corelanc0d3r - <peter.ve [at] corelan.be>
# http://www.corelan.be:8800/index.php/2010/10/12/death-of-an-ftp-client/
#
##

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::TcpServer

  def initialize
    super(
      'Name' => 'Simple FTP Client Fuzzer',
      'Description' => %q{
        This module will serve an FTP server and perform FTP client interaction fuzzing
      },
      'Author' => [ 'corelanc0d3r <peter.ve[at]corelan.be>' ],
      'License' => MSF_LICENSE,
      'References' => [
        [ 'URL', 'http://www.corelan.be:8800/index.php/2010/10/12/death-of-an-ftp-client/' ],
      ],
      'Notes' => {
        'Stability' => [CRASH_SERVICE_DOWN],
        'SideEffects' => [],
        'Reliability' => []
      }
    )
    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 21 ]),
        OptString.new('FUZZCMDS', [ true, 'Comma separated list of commands to fuzz (Uppercase).', 'LIST,NLST,LS,RETR', nil, /(?:[A-Z]+,?)+/ ]),
        OptInt.new('STARTSIZE', [ true, 'Fuzzing string startsize.', 1000]),
        OptInt.new('ENDSIZE', [ true, 'Max Fuzzing string size.', 200000]),
        OptInt.new('STEPSIZE', [ true, 'Increment fuzzing string each attempt.', 1000]),
        OptBool.new('RESET', [ true, 'Reset fuzzing values after client disconnects with QUIT cmd.', true]),
        OptString.new('WELCOME', [ true, 'FTP Server welcome message.', 'Evil FTP Server Ready']),
        OptBool.new('CYCLIC', [ true, "Use Cyclic pattern instead of A's (fuzzing payload).", true]),
        OptBool.new('ERROR', [ true, 'Reply with error codes only', false]),
        OptBool.new('EXTRALINE', [ true, "Add extra CRLF's in response to LIST", true])
      ]
    )
  end

  # Not compatible today
  def support_ipv6?
    false
  end

  def setup
    super
    @state = {}
  end

  def run
    @fuzzsize = datastore['STARTSIZE'].to_i
    exploit
  end

  # Handler for new FTP client connections
  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport,
      user: nil,
      pass: nil
    }
    # set up an active data port on port 20
    print_status("Client connected : #{client.peerhost}")
    active_data_port_for_client(client, 20)
    send_response(client, '', 'WELCOME', 220, ' ' + datastore['WELCOME'])
    # from this point forward, on_client_data() will take over
  end

  def on_client_close(client)
    @state.delete(client)
  end

  # Active and Passive data connections
  def passive_data_port_for_client(client)
    @state[client][:mode] = :passive
    if !(@state[client][:passive_sock])
      s = Rex::Socket::TcpServer.create(
        'LocalHost' => '0.0.0.0',
        'LocalPort' => 0,
        'Context' => { 'Msf' => framework, 'MsfExploit' => self }
      )
      dport = s.getsockname[2]
      @state[client][:passive_sock] = s
      @state[client][:passive_port] = dport
      print_status(" - Set up passive data port #{dport}")
    end
    @state[client][:passive_port]
  end

  def active_data_port_for_client(client, port)
    @state[client][:mode] = :active
    connector = proc do
      host = client.peerhost.dup
      Rex::Socket::Tcp.create(
        'PeerHost' => host,
        'PeerPort' => port,
        'Context' => { 'Msf' => framework, 'MsfExploit' => self }
      )
    end
    @state[client][:active_connector] = connector
    @state[client][:active_port] = port
    print_status(" - Set up active data port #{port}")
  end

  def establish_data_connection(client)
    print_status(" - Establishing #{@state[client][:mode]} data connection")
    begin
      Timeout.timeout(20) do
        if (@state[client][:mode] == :active)
          return @state[client][:active_connector].call
        end
        if (@state[client][:mode] == :passive)
          return @state[client][:passive_sock].accept
        end
      end
      print_status(' - Data connection active')
    rescue StandardError => e
      print_error("Failed to establish data connection: #{e.class} #{e}")
    end
    nil
  end

  # FTP Client-to-Server Command handlers
  def on_client_data(client)
    # get the client data
    data = client.get_once
    return if !data

    # split data into command and arguments
    cmd, arg = data.strip.split(/\s+/, 2)
    arg ||= ''

    return if !cmd

    # convert commands to uppercase and strip spaces
    case cmd.upcase.strip

    when 'USER'
      @state[client][:user] = arg
      send_response(client, arg, 'USER', 331, ' User name okay, need password')
      return

    when 'PASS'
      @state[client][:pass] = arg
      send_response(client, arg, 'PASS', 230, "-Password accepted.\r\n230 User logged in.")
      return

    when 'QUIT'
      if datastore['RESET']
        print_status('Resetting fuzz settings')
        @fuzzsize = datastore['STARTSIZE']
        @stepsize = datastore['STEPSIZE']
      end
      print_status('** Client disconnected **')
      send_response(client, arg, 'QUIT', 221, ' User logged out')
      return

    when 'SYST'
      send_response(client, arg, 'SYST', 215, ' UNIX Type: L8')
      return

    when 'TYPE'
      send_response(client, arg, 'TYPE', 200, " Type set to #{arg}")
      return

    when 'CWD'
      send_response(client, arg, 'CWD', 250, ' CWD Command successful')
      return

    when 'PWD'
      send_response(client, arg, 'PWD', 257, ' "/" is current directory.')
      return

    when 'REST'
      send_response(client, arg, 'REST', 200, ' OK')
      return

    when 'XPWD'
      send_response(client, arg, 'PWD', 257, ' "/" is current directory')
      return

    when 'SIZE'
      send_response(client, arg, 'SIZE', 213, ' 1')
      return

    when 'MDTM'
      send_response(client, arg, 'MDTM', 213, " #{Time.now.strftime('%Y%m%d%H%M%S')}")
      return

    when 'CDUP'
      send_response(client, arg, 'CDUP', 257, ' "/" is current directory')
      return

    when 'PORT'
      port = arg.split(',')[4, 2]
      if !port && (port.length == 2)
        client.put("500 Illegal PORT command.\r\n")
        return
      end
      port = port.map(&:to_i).pack('C*').unpack('n')[0]
      active_data_port_for_client(client, port)
      send_response(client, arg, 'PORT', 200, ' PORT command successful')
      return

    when 'PASV'
      print_status("Handling #{cmd.upcase} command")
      daddr = Rex::Socket.source_address(client.peerhost)
      dport = passive_data_port_for_client(client)
      @state[client][:daddr] = daddr
      @state[client][:dport] = dport
      pasv = (daddr.split('.') + [dport].pack('n').unpack('CC')).join(',')
      dofuzz = fuzz_this_cmd('PASV')
      code = 227
      if datastore['ERROR']
        code = 557
      end
      if (dofuzz == 1)
        print_status(" * Fuzzing response for PASV, payload length #{@fuzzdata.length}")
        send_response(client, arg, 'PASV', code, " Entering Passive Mode (#{@fuzzdata},1,1,1,1,1)\r\n")
        incr_fuzzsize
      else
        send_response(client, arg, 'PASV', code, " Entering Passive Mode (#{pasv})")
      end
      return

    when /^(LIST|NLST|LS)$/
      # special case - requires active/passive connection
      print_status("Handling #{cmd.upcase} command")
      conn = establish_data_connection(client)
      if !conn
        client.put("425 Can't build data connection\r\n")
        return
      end
      print_status(' - Data connection set up')
      code = 150
      if datastore['ERROR']
        code = 550
      end
      client.put("#{code} Here comes the directory listing.\r\n")
      code = 226
      if datastore['ERROR']
        code = 550
      end
      client.put("#{code} Directory send ok.\r\n")
      strfile = 'passwords.txt'
      strfolder = 'Secret files'
      dofuzz = fuzz_this_cmd('LIST')
      if (dofuzz == 1)
        strfile = @fuzzdata + '.txt'
        strfolder = @fuzzdata
        paylen = @fuzzdata.length
        print_status("* Fuzzing response for LIST, payload length #{paylen}")
        incr_fuzzsize
      end
      print_status(' - Sending directory list via data connection')
      if datastore['EXTRALINE']
        extra = "\r\n"
      else
        extra = ''
      end
      dirlist = "drwxrwxrwx    1 100      0           11111 Jun 11 21:10 #{strfolder}\r\n" + extra
      dirlist << "-rw-rw-r--    1 1176     1176         1060 Aug 16 22:22 #{strfile}\r\n" + extra
      conn.put("total 2\r\n" + dirlist)
      conn.close
      return

    when 'RETR'
      # special case - requires active/passive connection
      print_status("Handling #{cmd.upcase} command")
      conn = establish_data_connection(client)
      if !conn
        client.put("425 Can't build data connection\r\n")
        return
      end
      print_status(' - Data connection set up')
      strcontent = 'blahblahblah'
      dofuzz = fuzz_this_cmd('LIST')
      if (dofuzz == 1)
        strcontent = @fuzzdata
        paylen = @fuzzdata.length
        print_status("* Fuzzing response for RETR, payload length #{paylen}")
        incr_fuzzsize
      end
      client.put("150 Opening BINARY mode data connection #{strcontent}\r\n")
      print_status(' - Sending data via data connection')
      conn.put(strcontent)
      client.put("226 Transfer complete\r\n")
      conn.close
      return

    when /^(STOR|MKD|REM|DEL|RMD)$/
      send_response(client, arg, cmd.upcase, 500, ' Access denied')
      return

    when 'FEAT'
      send_response(client, arg, 'FEAT', '', "211-Features:\r\n211 End")
      return

    when 'HELP'
      send_response(client, arg, 'HELP', 214, " Syntax: #{arg} - (#{arg}-specific commands)")

    when 'SITE'
      send_response(client, arg, 'SITE', 200, ' OK')
      return

    when 'NOOP'
      send_response(client, arg, 'NOOP', 200, ' OK')
      return

    when 'ABOR'
      send_response(client, arg, 'ABOR', 225, ' Abor command successful')
      return

    when 'ACCT'
      send_response(client, arg, 'ACCT', 200, ' OK')
      return

    when 'RNFR'
      send_response(client, arg, 'RNRF', 350, ' File.exist')
      return

    when 'RNTO'
      send_response(client, arg, 'RNTO', 350, ' File.exist')
      return

    else
      send_response(client, arg, cmd.upcase, 200, ' Command not understood')
      return
    end

    return
  end

  # Fuzzer functions

  # Do we need to fuzz this command ?
  def fuzz_this_cmd(cmd)
    @fuzzcommands = datastore['FUZZCMDS'].split(',')

    fuzzme = 0
    @fuzzcommands.each do |thiscmd|
      if ((cmd.upcase == thiscmd.upcase) || (thiscmd == '*')) && (fuzzme == 0)
        fuzzme = 1
        break
      end
    end

    if fuzzme == 1
      # should we use a cyclic pattern, or just A's ?
      if datastore['CYCLIC']
        @fuzzdata = Rex::Text.pattern_create(@fuzzsize)
      else
        @fuzzdata = 'A' * @fuzzsize
      end
    end

    return fuzzme
  end

  def incr_fuzzsize
    @stepsize = datastore['STEPSIZE'].to_i
    @fuzzsize += @stepsize
    print_status("(i) Setting next payload size to #{@fuzzsize}")
    if (@fuzzsize > datastore['ENDSIZE'].to_i)
      @fuzzsize = datastore['ENDSIZE'].to_i
    end
  end

  # Send data back to the server
  def send_response(client, arg, cmd, code, msg)
    if arg.length > 40
      showarg = arg[0, 40] + '...'
    else
      showarg = arg
    end

    if cmd.length > 40
      showcmd = cmd[0, 40] + '...'
    else
      showcmd = cmd
    end

    print_status("Sending response for '#{showcmd}' command, arg #{showarg}")
    dofuzz = fuzz_this_cmd(cmd)

    ## Fuzz this command ?  (excluding PASV, which is handled in the command handler)
    if (dofuzz == 1) && (cmd.upcase != 'PASV')
      paylen = @fuzzdata.length
      print_status("* Fuzzing response for #{cmd.upcase}, payload length #{paylen}")
      if datastore['ERROR']
        code = '550 '
      end
      if cmd == 'FEAT'
        @fuzzdata = "211-Features:\r\n " + @fuzzdata + "\r\n211 End"
      end
      if cmd == 'PWD'
        @fuzzdata = '  "/' + @fuzzdata + '" is current directory'
      end
      cmsg = code.to_s + ' ' + @fuzzdata
      client.put("#{cmsg}\r\n")
      print_status('* Fuzz data sent')
      incr_fuzzsize
    else
      # Do not fuzz
      cmsg = code.to_s + msg
      cmsg = cmsg.strip
      client.put("#{cmsg}\r\n")
    end
  end
end
