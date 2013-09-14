##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
# Fuzzer written by corelanc0d3r - <peter.ve [at] corelan.be>
# http://www.corelan.be:8800/index.php/2010/10/12/death-of-an-ftp-client/
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Exploit::Remote::TcpServer

  def initialize()
    super(
      'Name'           => 'Simple FTP Client Fuzzer',
      'Description'    => %q{
        This module will serve an FTP server and perform FTP client interaction fuzzing
      },
      'Author'         => [ 'corelanc0d3r <peter.ve[at]corelan.be>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.corelan.be:8800/index.php/2010/10/12/death-of-an-ftp-client/' ],
        ]
      )
    register_options(
      [
      OptPort.new('SRVPORT', [ true, "The local port to listen on.", 21 ]),
      OptString.new('FUZZCMDS', [ true, "Comma separated list of commands to fuzz.", "LIST,NLST,LS,RETR" ]),
      OptInt.new('STARTSIZE', [ true, "Fuzzing string startsize.",1000]),
      OptInt.new('ENDSIZE', [ true, "Max Fuzzing string size.",200000]),
      OptInt.new('STEPSIZE', [ true, "Increment fuzzing string each attempt.",1000]),
      OptBool.new('RESET', [ true, "Reset fuzzing values after client disconnects with QUIT cmd.",true]),
      OptString.new('WELCOME', [ true, "FTP Server welcome message.","Evil FTP Server Ready"]),
      OptBool.new('CYCLIC', [ true, "Use Cyclic pattern instead of A's (fuzzing payload).",true]),
      OptBool.new('ERROR', [ true, "Reply with error codes only",false]),
      OptBool.new('EXTRALINE', [ true, "Add extra CRLF's in response to LIST",true])
      ], self.class)
  end


  # Not compatible today
  def support_ipv6?
    false
  end


  #---------------------------------------------------------------------------------
  def setup
    super
    @state = {}
  end


  #---------------------------------------------------------------------------------

  def run
    @fuzzsize=datastore['STARTSIZE'].to_i
    exploit()
  end

  #---------------------------------------------------------------------------------
  # Handler for new FTP client connections
  #---------------------------------------------------------------------------------

  def on_client_connect(c)
    @state[c] = {
      :name => "#{c.peerhost}:#{c.peerport}",
      :ip   => c.peerhost,
      :port => c.peerport,
      :user => nil,
      :pass => nil
    }
    #set up an active data port on port 20
    print_status("Client connected : " + c.peerhost)
    active_data_port_for_client(c, 20)
    send_response(c,"","WELCOME",220," "+datastore['WELCOME'])
    #from this point forward, on_client_data() will take over
  end

  def on_client_close(c)
    @state.delete(c)
  end

  #---------------------------------------------------------------------------------
  # Active and Passive data connections
  #---------------------------------------------------------------------------------
  def passive_data_port_for_client(c)
    @state[c][:mode] = :passive
    if(not @state[c][:passive_sock])
      s = Rex::Socket::TcpServer.create(
        'LocalHost' => '0.0.0.0',
        'LocalPort' => 0,
        'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
      )
      dport = s.getsockname[2]
      @state[c][:passive_sock] = s
      @state[c][:passive_port] = dport
      print_status(" - Set up passive data port #{dport}")
    end
    @state[c][:passive_port]
  end


  def active_data_port_for_client(c,port)
    @state[c][:mode] = :active
    connector = Proc.new {
      host = c.peerhost.dup
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => host,
        'PeerPort' => port,
        'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
      )
    }
    @state[c][:active_connector] = connector
    @state[c][:active_port]      = port
    print_status(" - Set up active data port #{port}")
  end


  def establish_data_connection(c)
    print_status(" - Establishing #{@state[c][:mode]} data connection")
    begin
    Timeout.timeout(20) do
      if(@state[c][:mode] == :active)
        return @state[c][:active_connector].call()
      end
      if(@state[c][:mode] == :passive)
        return @state[c][:passive_sock].accept
      end
    end
    print_status(" - Data connection active")
    rescue ::Exception => e
      print_error("Failed to establish data connection: #{e.class} #{e}")
    end
    nil
  end



  #---------------------------------------------------------------------------------
  #  FTP Client-to-Server Command handlers
  #---------------------------------------------------------------------------------

  def on_client_data(c)
    #get the client data
    data = c.get_once
    return if not data
    #split data into command and arguments
    cmd,arg = data.strip.split(/\s+/, 2)
    arg ||= ""

    return if not cmd
    #convert commands to uppercase and strip spaces
    case cmd.upcase.strip

    when 'USER'
      @state[c][:user] = arg
      send_response(c,arg,"USER",331," User name okay, need password")
      return

    when 'PASS'
      @state[c][:pass] = arg
      send_response(c,arg,"PASS",230,"-Password accepted.\r\n230 User logged in.")
      return

    when 'QUIT'
      if (datastore['RESET'])
        print_status("Resetting fuzz settings")
        @fuzzsize = datastore['STARTSIZE']
        @stepsize = datastore['STEPSIZE']
      end
      print_status("** Client disconnected **")
      send_response(c,arg,"QUIT",221," User logged out")
      return

    when 'SYST'
      send_response(c,arg,"SYST",215," UNIX Type: L8")
      return

    when 'TYPE'
      send_response(c,arg,"TYPE",200," Type set to #{arg}")
      return

    when 'CWD'
      send_response(c,arg,"CWD",250," CWD Command successful")
      return

    when 'PWD'
      send_response(c,arg,"PWD",257," \"/\" is current directory.")
      return

    when 'REST'
      send_response(c,arg,"REST",200," OK")
      return

    when 'XPWD'
      send_response(c,arg,"PWD",257," \"/\" is current directory")
      return

    when 'SIZE'
      send_response(c,arg,"SIZE",213," 1")
      return

    when 'MDTM'
      send_response(c,arg,"MDTM",213," #{Time.now.strftime("%Y%m%d%H%M%S")}")
      return

    when 'CDUP'
      send_response(c,arg,"CDUP",257," \"/\" is current directory")
      return

    when 'PORT'
      port = arg.split(',')[4,2]
      if(not port and port.length == 2)
        c.put("500 Illegal PORT command.\r\n")
        return
      end
      port = port.map{|x| x.to_i}.pack('C*').unpack('n')[0]
      active_data_port_for_client(c, port)
      send_response(c,arg,"PORT",200," PORT command successful")
      return

    when 'PASV'
      print_status("Handling #{cmd.upcase} command")
      daddr = Rex::Socket.source_address(c.peerhost)
      dport = passive_data_port_for_client(c)
      @state[c][:daddr] = daddr
      @state[c][:dport] = dport
      pasv  = (daddr.split('.') + [dport].pack('n').unpack('CC')).join(',')
      dofuzz = fuzz_this_cmd("PASV")
      code = 227
      if datastore['ERROR']
        code = 557
      end
      if (dofuzz==1)
        print_status(" * Fuzzing response for PASV, payload length #{@fuzzdata.length}")
        send_response(c,arg,"PASV",code," Entering Passive Mode (#{@fuzzdata},1,1,1,1,1)\r\n")
        incr_fuzzsize()
      else
        send_response(c,arg,"PASV",code," Entering Passive Mode (#{pasv})")
      end
      return

    when /^(LIST|NLST|LS)$/
      #special case - requires active/passive connection
      print_status("Handling #{cmd.upcase} command")
      conn = establish_data_connection(c)
      if(not conn)
        c.put("425 Can't build data connection\r\n")
        return
      end
      print_status(" - Data connection set up")
      code = 150
      if datastore['ERROR']
        code = 550
      end
      c.put("#{code} Here comes the directory listing.\r\n")
      code = 226
      if datastore['ERROR']
        code = 550
      end
      c.put("#{code} Directory send ok.\r\n")
      strfile = "passwords.txt"
      strfolder = "Secret files"
      dofuzz = fuzz_this_cmd("LIST")
      if (dofuzz==1)
        strfile = @fuzzdata + ".txt"
        strfolder = @fuzzdata
        paylen = @fuzzdata.length
        print_status("* Fuzzing response for LIST, payload length #{paylen}")
        incr_fuzzsize()
      end
      print_status(" - Sending directory list via data connection")
      dirlist = ""
      if datastore['EXTRALINE']
        extra = "\r\n"
      else
        extra = ""
      end
      dirlist = "drwxrwxrwx    1 100      0           11111 Jun 11 21:10 #{strfolder}\r\n" + extra
      dirlist << "-rw-rw-r--    1 1176     1176         1060 Aug 16 22:22 #{strfile}\r\n" + extra
      conn.put("total 2\r\n"+dirlist)
      conn.close
      return

    when 'RETR'
      #special case - requires active/passive connection
      print_status("Handling #{cmd.upcase} command")
      conn = establish_data_connection(c)
      if(not conn)
        c.put("425 Can't build data connection\r\n")
        return
      end
      print_status(" - Data connection set up")
      strcontent = "blahblahblah"
      dofuzz = fuzz_this_cmd("LIST")
      if (dofuzz==1)
        strcontent = @fuzzdata
        paylen = @fuzzdata.length
        print_status("* Fuzzing response for RETR, payload length #{paylen}")
        incr_fuzzsize()
      end
      c.put("150 Opening BINARY mode data connection #{strcontent}\r\n")
      print_status(" - Sending data via data connection")
      conn.put(strcontent)
      c.put("226 Transfer complete\r\n")
      conn.close
      return

    when /^(STOR|MKD|REM|DEL|RMD)$/
      send_response(c,arg,cmd.upcase,500," Access denied")
      return

    when 'FEAT'
      send_response(c,arg,"FEAT","","211-Features:\r\n211 End")
      return

    when 'HELP'
      send_response(c,arg,"HELP",214," Syntax: #{arg} - (#{arg}-specific commands)")

    when 'SITE'
      send_response(c,arg,"SITE",200," OK")
      return

    when 'NOOP'
      send_response(c,arg,"NOOP",200," OK")
      return

    when 'ABOR'
      send_response(c,arg,"ABOR",225," Abor command successful")
      return

    when 'ACCT'
      send_response(c,arg,"ACCT",200," OK")
      return

    when 'RNFR'
      send_response(c,arg,"RNRF",350," File exists")
      return

    when 'RNTO'
      send_response(c,arg,"RNTO",350," File exists")
      return
    else
      send_response(c,arg,cmd.upcase,200," Command not understood")
      return
    end
    return
  end



  #---------------------------------------------------------------------------------
  # Fuzzer functions
  #---------------------------------------------------------------------------------

  # Do we need to fuzz this command ?
  def fuzz_this_cmd(cmd)
    @fuzzcommands = datastore['FUZZCMDS'].split(",")
    fuzzme = 0
    @fuzzcommands.each do |thiscmd|
      if ((cmd.upcase == thiscmd.upcase) || (thiscmd=="*")) && (fuzzme==0)
        fuzzme = 1
      end
    end
    if fuzzme==1
      # should we use a cyclic pattern, or just A's ?
      if datastore['CYCLIC']
        @fuzzdata = Rex::Text.pattern_create(@fuzzsize)
      else
        @fuzzdata = "A" * @fuzzsize
      end
    end
    return fuzzme
  end

  def incr_fuzzsize
    @stepsize = datastore['STEPSIZE'].to_i
    @fuzzsize = @fuzzsize + @stepsize
    print_status("(i) Setting next payload size to #{@fuzzsize}")
    if (@fuzzsize > datastore['ENDSIZE'].to_i)
      @fuzzsize = datastore['ENDSIZE'].to_i
    end
  end


  # Send data back to the server
  def send_response(c,arg,cmd,code,msg)
    if arg.length > 40
      showarg = arg[0,40] + "..."
    else
      showarg = arg
    end
    if cmd.length > 40
      showcmd = cmd[0,40] + "..."
    else
      showcmd = cmd
    end
    print_status("Sending response for '#{showcmd}' command, arg #{showarg}")
    dofuzz = fuzz_this_cmd(cmd)
    ## Fuzz this command ?  (excluding PASV, which is handled in the command handler)
    if (dofuzz==1) && (cmd.upcase != "PASV")
      paylen = @fuzzdata.length
      print_status("* Fuzzing response for #{cmd.upcase}, payload length #{paylen}")
      if datastore['ERROR']
        code = "550 "
      end
      if cmd=="FEAT"
        @fuzzdata = "211-Features:\r\n "+@fuzzdata+"\r\n211 End"
      end
      if cmd=="PWD"
        @fuzzdata = "  \"/"+@fuzzdata+"\" is current directory"
      end
      cmsg = code.to_s + " " + @fuzzdata
      c.put("#{cmsg}\r\n")
      print_status("* Fuzz data sent")
      incr_fuzzsize()
    else
      #Do not fuzz
      cmsg = code.to_s + msg
      cmsg = cmsg.strip
      c.put("#{cmsg}\r\n")
    end
    return
  end
end
