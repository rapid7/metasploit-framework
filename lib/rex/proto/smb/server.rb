# -*- coding: binary -*-
require 'rex/socket'
require 'rex/proto/smb'
require 'rex/text'
require 'rex/logging'
require 'rex/struct2'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/utils'
require 'rex/proto/dcerpc'

module Rex
module Proto
module SMB

###
#
# Runtime extension of the SMB clients that connect to the server.
#
###
module ServerClient

  #
  # Initialize a new request instance.
  #
  def init_cli(server)
    self.server = server
  end

  #
  # Transmits a response and adds the appropriate headers.
  #
  def send_response(response)
    # Send it off.
    put(response.to_s)
  end

  #
  # The current request context.
  #
  attr_accessor :request
  #
  # A reference to the server the client is associated with.
  #
  attr_accessor :server

end

##
#
# SMB Server class
#
##
class Server

# Read Write
  attr_accessor :listen_port, :listen_host, :context
  attr_accessor :listener
  attr_accessor :process_id, :name, :ip, :port, :data
  attr_accessor :user_id, :tree_id, :multiplex_id
  attr_accessor :debugging

# Read Only
  attr_reader :hi, :lo

  CONST = Rex::Proto::SMB::Constants
  UTILS = Rex::Proto::SMB::Utils

  #
  # Setup State
  #
  def initialize(port, listen_host, context = {})
    self.listen_host = listen_host
    self.listen_port = port
    self.context     = context
    self.listener    = nil
    self.multiplex_id = rand(0xffff)
    self.process_id   = rand(0xffff)
    @state = {}
  end

  #
  # Debug
  #
  def dprint(msg)
    return if not self.debugging
    $stdout.puts "#{msg}"
  end

  #
  # SMB server.
  #
  def alias
    super || "SMBServer"
  end

  #
  # Listens on the defined port and host and starts monitoring for clients.
  #
  def start

    params = {
      'LocalHost' => self.listen_host,
      'LocalPort' => self.listen_port,
      'Context'   => self.context,
    }

    self.listener = Rex::Socket::TcpServer.create( params )

    # Register callbacks
    self.listener.on_client_connect_proc = Proc.new { |client|
      on_client_connect(client)
    }
    self.listener.on_client_data_proc = Proc.new { |client|
      on_client_data(client)
    }
    self.listener.start
  end

  #
  # Terminates the monitor thread and turns off the listener.
  #
  def stop
    self.listener.stop
    self.listener.close
  end

  #
  # Waits for the SMB service to terminate
  #
  def wait
    self.listener.wait if self.listener
  end

  #
  # Register globals
  #
  def register(unc, contents, exe_file, hi, lo)
      @unc = unc
      @exe_file = exe_file
      @hi = hi
      @lo = lo
      @exe = contents
      @flags2 = 0xc807 # c801 or c001
  end

protected

  def on_client_connect(client)
    dprint("New SMB connection from #{client.peerhost}:#{client.peerport}")
    smb_conn(client)
  end

  def on_client_data(client)
    dprint("New data from #{client.peerhost}:#{client.peerport}")
    smb_recv(client)
    true
  end

  def smb_conn(c)
    @state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport}
  end

  def smb_stop(c)
    @state.delete(c)
  end

  def smb_recv(c)
    smb = @state[c]
    data = c.get_once
    return if not data
    smb[:data] = data

    while(smb[:data].length > 0)
      return if smb[:data].length < 4

      plen = smb[:data][2,2].unpack('n')[0]

      return if smb[:data].length < plen+4

      buff = smb[:data].slice!(0, plen+4)

      pkt_nbs = CONST::NBRAW_PKT.make_struct
      pkt_nbs.from_s(buff)

      dprint("NetBIOS request from #{smb[:name]} #{pkt_nbs.v['Type']} #{pkt_nbs.v['Flags']} #{buff.inspect}")

      # Check for a NetBIOS name request
      if (pkt_nbs.v['Type'] == 0x81)
        # Accept any name they happen to send

        host_dst = UTILS.nbname_decode(pkt_nbs.v['Payload'][1,32]).gsub(/[\x00\x20]+$/n, '')
        host_src = UTILS.nbname_decode(pkt_nbs.v['Payload'][35,32]).gsub(/[\x00\x20]+$/n, '')

        smb[:nbdst] = host_dst
        smb[:nbsrc] = host_src

        dprint("NetBIOS session request from #{smb[:name]} (asking for #{host_dst} from #{host_src})")
        c.write("\x82\x00\x00\x00")
        next
      end

      # Cast this to a generic SMB structure
      pkt = CONST::SMB_BASE_PKT.make_struct
      pkt.from_s(buff)

      # Only response to requests, ignore server replies
      if (pkt['Payload']['SMB'].v['Flags1'] & 128 != 0)
        dprint("Ignoring server response from #{smb[:name]}")
        next
      end

      cmd = pkt['Payload']['SMB'].v['Command']
      begin
        smb_cmd_dispatch(cmd, c, buff)
      rescue ::Interrupt
        raise $!
      rescue ::Exception => e
        dprint("Error processing request from #{smb[:name]} (#{cmd}): #{e.class} #{e} #{e.backtrace}")
        next
      end
    end
  end

  def smb_set_defaults(c, pkt)
    smb = @state[c]
    pkt['Payload']['SMB'].v['ProcessID'] = self.process_id.to_i
    pkt['Payload']['SMB'].v['UserID'] = self.user_id.to_i
    pkt['Payload']['SMB'].v['TreeID'] = self.tree_id.to_i
    pkt['Payload']['SMB'].v['MultiplexID'] = self.multiplex_id.to_i
  end

  def smb_error(cmd, c, errorclass, esn = false)
    # 0xc0000022 = Deny
    # 0xc000006D = Logon_Failure
    # 0x00000000 = Ignore
    pkt = CONST::SMB_BASE_PKT.make_struct
    smb_set_defaults(c, pkt)
    pkt['Payload']['SMB'].v['Command'] = cmd
    pkt['Payload']['SMB'].v['Flags1']  = 0x88
    if esn
      pkt['Payload']['SMB'].v['Flags2']  = 0xc801
    else
      pkt['Payload']['SMB'].v['Flags2']  = 0xc001
    end
    pkt['Payload']['SMB'].v['ErrorClass'] = errorclass
    c.put(pkt.to_s)
  end

  def smb_cmd_dispatch(cmd, c, buff)
    smb = @state[c]
    dprint("Received command " + cmd.to_s(16) + " from #{smb[:name]}")

    pkt = CONST::SMB_BASE_PKT.make_struct
    pkt.from_s(buff)
    #Record the IDs
    self.process_id = pkt['Payload']['SMB'].v['ProcessID']
    self.user_id = pkt['Payload']['SMB'].v['UserID']
    self.tree_id = pkt['Payload']['SMB'].v['TreeID']
    self.multiplex_id = pkt['Payload']['SMB'].v['MultiplexID']

    case cmd
      when CONST::SMB_COM_NEGOTIATE
        smb_cmd_negotiate(c, buff)
      when CONST::SMB_COM_SESSION_SETUP_ANDX
        wordcount = pkt['Payload']['SMB'].v['WordCount']
        if wordcount == 0x0D # It's the case for Share Security Mode sessions
          dprint("[smb_cmd_session_setup] wordcount is: " + wordcount.to_s)
          smb_cmd_session_setup(c, buff)
        #elsif wordcount == 0x0C # Also Share Security Mode sessions with NTLMSSP
        #  dprint("[smb_cmd_ntlmssp_session_setup] wordcount is: " + wordcount.to_s)
        # smb_cmd_ntlmssp_session_setup(c, buff)
        else
          dprint("SMB Capture - #{smb[:ip]} Unknown SMB_COM_SESSION_SETUP_ANDX request type , ignoring... ")
          smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS)
        end
      when CONST::SMB_COM_TRANSACTION2
        smb_cmd_trans(c, buff)
      when CONST::SMB_COM_NT_CREATE_ANDX
        smb_cmd_create(c, buff)
      when CONST::SMB_COM_READ_ANDX
        smb_cmd_read(c, buff)
      when CONST::SMB_COM_CLOSE
        smb_cmd_close(c, buff)
      else
        dprint("SMB Capture - Ignoring request from #{smb[:name]} - #{smb[:ip]} (#{cmd})")
        smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS)
    end
  end

  def smb_cmd_negotiate(c, buff)
    pkt = CONST::SMB_NEG_PKT.make_struct
    pkt.from_s(buff)

    dialects = pkt['Payload'].v['Payload'].gsub(/\x00/, '').split(/\x02/).grep(/^\w+/)

    dialect = dialects.index("NT LM 0.12") || dialects.length-1

    pkt = CONST::SMB_NEG_RES_NT_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NEGOTIATE
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 17
    pkt['Payload'].v['Dialect'] = dialect
    pkt['Payload'].v['SecurityMode'] = 2 # SHARE Security Mode
    #pkt['Payload'].v['SecurityMode'] = 3 # USER Security Mode
    pkt['Payload'].v['MaxMPX'] = 50
    pkt['Payload'].v['MaxVCS'] = 1
    pkt['Payload'].v['MaxBuff'] = 16644
    pkt['Payload'].v['MaxRaw'] = 65536
    pkt['Payload'].v['SystemTimeLow'] = @lo
    pkt['Payload'].v['SystemTimeHigh'] = @hi
    pkt['Payload'].v['ServerTimeZone'] = 0x0
    pkt['Payload'].v['SessionKey'] = 0
    #pkt['Payload'].v['Capabilities'] = 0x8080f3fd
    pkt['Payload'].v['Capabilities'] = 0xd4 # XXX: Capabilities is 0x8080f3fd. XXX: Bug if we support capabilities including NTLMSSP
    pkt['Payload'].v['KeyLength'] = 8
    pkt['Payload'].v['Payload'] = Rex::Text.rand_text_hex(8)

    c.put(pkt.to_s)
  end

  def smb_cmd_ntlmssp_session_setup(c, buff)
    # TODO: Can't be arsed to implement ntlmssp yet
    dprint("Broken here...")

    pkt = CONST::SMB_SETUP_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 4
    pkt['Payload'].v['AndX'] = 0xff
    pkt['Payload'].v['Reserved1'] = 00
    pkt['Payload'].v['AndXOffset'] = 0
    pkt['Payload'].v['Action'] = 0 # Not Logged in as GUEST
    pkt['Payload'].v['Payload'] =
      Rex::Text.to_unicode("Unix", 'utf-16be') + "\x00\x00" + # Native OS # Samba signature
      Rex::Text.to_unicode("Samba 3.4.7", 'utf-16be') + "\x00\x00" + # Native LAN Manager # Samba signature
      Rex::Text.to_unicode("WORKGROUP", 'utf-16be') + "\x00\x00\x00" + # Primary DOMAIN # Samba signature
    tree_connect_response = ""
    tree_connect_response << [7].pack("C")  # Tree Connect Response : WordCount
    tree_connect_response << [0xff].pack("C") # Tree Connect Response : AndXCommand
    tree_connect_response << [0].pack("C") # Tree Connect Response : Reserved
    tree_connect_response << [0].pack("v")  # Tree Connect Response : AndXOffset
    tree_connect_response << [0x1].pack("v")  # Tree Connect Response : Optional Support
    tree_connect_response << [0xff].pack("C") # Perms
    tree_connect_response << [0x01].pack("C")
    tree_connect_response << [0x1f].pack("C")
    tree_connect_response << [0xff].pack("C")
    tree_connect_response << [0].pack("v") # Tree Connect Response : Word Parameter
    tree_connect_response << [0].pack("v") # Tree Connect Response : Word Parameter
    tree_connect_response << [13].pack("v") # Tree Connect Response : ByteCount
    tree_connect_response << "A:\x00" # Service
    tree_connect_response << "#{Rex::Text.to_unicode("NTFS")}\x00\x00" # Extra byte parameters
    # Fix the Netbios Session Service Message Length
    # to have into account the tree_connect_response,
    # need to do this because there isn't support for
    # AndX still
    my_pkt = pkt.to_s + tree_connect_response
    original_length = my_pkt[2, 2].unpack("n").first
    original_length = original_length +  tree_connect_response.length
    my_pkt[2, 2] = [original_length].pack("n")
    c.put(my_pkt)
  end

  def smb_cmd_session_setup(c, buff)
    pkt = CONST::SMB_SETUP_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 3
    pkt['Payload'].v['AndX'] = 0x75
    pkt['Payload'].v['Reserved1'] = 00
    pkt['Payload'].v['AndXOffset'] = 96
    pkt['Payload'].v['Action'] = 0x1 # Logged in as Guest
    pkt['Payload'].v['Payload'] =
      Rex::Text.to_unicode("Unix", 'utf-16be') + "\x00\x00" + # Native OS # Samba signature
      Rex::Text.to_unicode("Samba 3.4.7", 'utf-16be') + "\x00\x00" + # Native LAN Manager # Samba signature
      Rex::Text.to_unicode("WORKGROUP", 'utf-16be') + "\x00\x00\x00" + # Primary DOMAIN # Samba signature
    tree_connect_response = ""
    tree_connect_response << [7].pack("C")  # Tree Connect Response : WordCount
    tree_connect_response << [0xff].pack("C") # Tree Connect Response : AndXCommand
    tree_connect_response << [0].pack("C") # Tree Connect Response : Reserved
    tree_connect_response << [0].pack("v")  # Tree Connect Response : AndXOffset
    tree_connect_response << [0x1].pack("v")  # Tree Connect Response : Optional Support
    tree_connect_response << [0xff].pack("C") # Perms
    tree_connect_response << [0x01].pack("C")
    tree_connect_response << [0x1f].pack("C")
    tree_connect_response << [0xff].pack("C")
    tree_connect_response << [0].pack("v") # Tree Connect Response : Word Parameter
    tree_connect_response << [0].pack("v") # Tree Connect Response : Word Parameter
    tree_connect_response << [13].pack("v") # Tree Connect Response : ByteCount
    tree_connect_response << "A:\x00" # Service
    tree_connect_response << "#{Rex::Text.to_unicode("NTFS")}\x00\x00" # Extra byte parameters
    # Fix the Netbios Session Service Message Length
    # to have into account the tree_connect_response,
    # need to do this because there isn't support for
    # AndX still
    my_pkt = pkt.to_s + tree_connect_response
    original_length = my_pkt[2, 2].unpack("n").first
    original_length = original_length +  tree_connect_response.length
    my_pkt[2, 2] = [original_length].pack("n")
    c.put(my_pkt)
  end

  def smb_cmd_create(c, buff)
    pkt = CONST::SMB_CREATE_PKT.make_struct
    pkt.from_s(buff)

    # Tries to do CREATE and X
    payload = pkt['Payload'].v['Payload'].gsub(/\x00/, '').gsub(/.*\\/, '\\')
    file = Rex::Text.to_unicode(@exe_file)
    length = pkt['Payload'].v['Payload'].length
    dprint("[create_and_x] Payload is: " + payload)
    dprint("[create_and_x] Payload length is: " + payload.length.to_s)
    fname = @exe_file.length + 1 # Add the "\"

    if length >= fname
      # Asks for something other than a directory, like our exploit
      dprint("[create_and_x] Sending file response: " + file + " with length: " + @exe.length.to_s)
      pkt = CONST::SMB_CREATE_RES_PKT.make_struct
      smb_set_defaults(c, pkt)
      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX
      pkt['Payload']['SMB'].v['Flags1'] = 0x88
      pkt['Payload']['SMB'].v['Flags2'] = @flags2
      pkt['Payload']['SMB'].v['WordCount'] = 42
      pkt['Payload'].v['AndX'] = 0xff # no further commands
      pkt['Payload'].v['OpLock'] = 0x3 # Grant Oplock on File
      # No need to track fid here, we're just offering one file
      pkt['Payload'].v['FileID'] = rand(0x7fff) + 1 # To avoid fid = 0
      pkt['Payload'].v['Action'] = 0x1 # The file existed and was opened
      pkt['Payload'].v['CreateTimeLow'] = @lo
      pkt['Payload'].v['CreateTimeHigh'] = @hi
      pkt['Payload'].v['AccessTimeLow'] = @lo
      pkt['Payload'].v['AccessTimeHigh'] = @hi
      pkt['Payload'].v['WriteTimeLow'] = @lo
      pkt['Payload'].v['WriteTimeHigh'] = @hi
      pkt['Payload'].v['ChangeTimeLow'] = @lo
      pkt['Payload'].v['ChangeTimeHigh'] = @hi
      pkt['Payload'].v['Attributes'] = 0x20 # Not an archive
      pkt['Payload'].v['AllocLow'] = 1048576 # 1Mb
      pkt['Payload'].v['AllocHigh'] = 0
      pkt['Payload'].v['EOFLow'] = @exe.length
      pkt['Payload'].v['EOFHigh'] = 0
      pkt['Payload'].v['FileType'] = 0
      pkt['Payload'].v['IPCState'] = 0x7
      pkt['Payload'].v['IsDirectory'] = 0
    elsif length < fname
      # Asks for a directory
      dprint("[create_and_x] Sending directory response")
      pkt = CONST::SMB_CREATE_RES_PKT.make_struct
      smb_set_defaults(c, pkt)
      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX
      pkt['Payload']['SMB'].v['Flags1'] = 0x88
      pkt['Payload']['SMB'].v['Flags2'] = @flags2
      pkt['Payload']['SMB'].v['WordCount'] = 42
      pkt['Payload'].v['AndX'] = 0xff # no further commands
      pkt['Payload'].v['OpLock'] = 0 # Deny OpLock on Directory
      # No need to track fid here, we're just offering one file
      pkt['Payload'].v['FileID'] = rand(0x7fff) + 1 # To avoid fid = 0
      pkt['Payload'].v['Action'] = 0x1 # The file existed and was opened
      pkt['Payload'].v['CreateTimeLow'] = @lo
      pkt['Payload'].v['CreateTimeHigh'] = @hi
      pkt['Payload'].v['AccessTimeLow'] = @lo
      pkt['Payload'].v['AccessTimeHigh'] = @hi
      pkt['Payload'].v['WriteTimeLow'] = @lo
      pkt['Payload'].v['WriteTimeHigh'] = @hi
      pkt['Payload'].v['ChangeTimeLow'] = @lo
      pkt['Payload'].v['ChangeTimeHigh'] = @hi
      pkt['Payload'].v['Attributes'] = 0x10 # Ordinary dir
      pkt['Payload'].v['AllocLow'] = 0
      pkt['Payload'].v['AllocHigh'] = 0
      pkt['Payload'].v['EOFLow'] = 0
      pkt['Payload'].v['EOFHigh'] = 0
      pkt['Payload'].v['FileType'] = 0
      pkt['Payload'].v['IPCState'] = 0x7
      pkt['Payload'].v['IsDirectory'] = 1
    end

    if length >= 1
      connect_response = ""
      # GUID
      connect_response << ([0].pack("C") * 16)
      # File ID
      connect_response << ([0].pack("C") * 8)
      # Access Rights
      connect_response << [0xff].pack("C")
      connect_response << [0x01].pack("C")
      connect_response << [0x1f].pack("C")
      connect_response << [0].pack("C")
      connect_response << ([0].pack("C") * 4) # Guest access
      connect_response << ([0].pack("C") * 2) # Byte Count

      my_pkt = pkt.to_s + connect_response
      original_length = my_pkt[2, 2].unpack("n").first
      original_length = original_length + connect_response.length
      my_pkt[2, 2] = [original_length].pack("n")
      c.put(my_pkt)
    else
      pkt = CONST::SMB_CREATE_RES_PKT.make_struct
      smb_set_defaults(c, pkt)
      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX
      pkt['Payload']['SMB'].v['ErrorClass'] = 0xC0000034 # OBJECT_NAME_NOT_FOUND
      pkt['Payload']['SMB'].v['Flags1'] = 0x88
      pkt['Payload']['SMB'].v['Flags2'] = @flags2
      c.put(pkt.to_s)
    end
  end

  def smb_cmd_close(c, buff)
    pkt = CONST::SMB_CLOSE_PKT.make_struct
    pkt.from_s(buff)

    pkt = CONST::SMB_CLOSE_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_CLOSE
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 0

    c.put(pkt.to_s)
  end

  def smb_cmd_read(c, buff)
    pkt = CONST::SMB_READ_PKT.make_struct
    pkt.from_s(buff)

    offset = pkt['Payload'].v['Offset']
    length = pkt['Payload'].v['MaxCountLow']

    pkt = CONST::SMB_READ_RES_PKT.make_struct
    smb_set_defaults(c, pkt)
    dprint("Sending File! Offset: " + offset.to_s + " Length: " + length.to_s)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_READ_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 12
    pkt['Payload'].v['AndX'] = 0xff # no more commands
    pkt['Payload'].v['Remaining'] = 0xffff
    pkt['Payload'].v['DataLenLow'] = length
    pkt['Payload'].v['DataOffset'] = 59
    pkt['Payload'].v['DataLenHigh'] = 0
    pkt['Payload'].v['Reserved3'] = 0
    pkt['Payload'].v['Reserved4'] = 0x0a
    pkt['Payload'].v['ByteCount'] = length
    pkt['Payload'].v['Payload'] = @exe[offset, length]
    c.put(pkt.to_s)
  end

  def bin_to_hex(s)
    s.unpack('H*').first
  end

  def hex_to_bin(s)
    s.scan(/../).map { |x| x.hex }.pack('c*')
  end

  def smb_cmd_trans(c, buff)
    # Client socket is c
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    sub_command = pkt['Payload'].v['SetupData'].unpack("v").first
    dprint("Command is: " + sub_command.to_s)
    ar = bin_to_hex(buff).to_s
    mdc = ar[86..89]
    loi = ar[144..147] # LOI is random I think, its MDC that counts?

    case sub_command
      when 0x24 # QUERY_FILE_INFO
        dprint("[query_file_info_24]")
        #smb_cmd_trans_query_file_info_standard(c, buff)
        # path info works here
        smb_cmd_trans_query_path_info_standard(c, buff)
      when 0x7 # QUERY_FILE_INFO
        dprint("[query_file_info_7]")
        # path info works here
        smb_cmd_trans_query_path_info_standard(c, buff)
      when 0x5 # QUERY_PATH_INFO
       dprint("[query_path_info]")
       #dprint("LOI is: " + loi)
       dprint("MDC is: " + mdc)
       case mdc # MAX DATA COUNT
        when '2800'
          # Basic is 1004 (ec03) (MDC = 40 / 2800 hex)
          dprint("[query_path_info_basic]")
          smb_cmd_trans_query_path_info_basic(c, buff)
        when '1800', '0201'
          # Standard is 1005 (ed03) (MDC = 24 / 1800 hex) or 258 (0201)
          dprint("[query_path_info_standard]")
          smb_cmd_trans_query_path_info_standard(c, buff)
        when '0800'
          # Internal File info is 1006 (ee03) (MDC = 8 / 0800 hex)
          dprint("[query_file_info_basic]")
          smb_cmd_trans_query_file_info_standard(c, buff)
        else
          dprint("Unknown MDC - Sending to [query_path_info_standard]: " + mdc.to_s)
          smb_cmd_trans_query_path_info_standard(c, buff)
        end
      when 0x1 # FIND_FIRST2
        dprint("find_first2")
        smb_cmd_trans_find_first2(c, buff)
      else
        pkt = CONST::SMB_TRANS_RES_PKT.make_struct
        smb_set_defaults(c, pkt)
        pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
        pkt['Payload']['SMB'].v['Flags1'] = 0x88
        pkt['Payload']['SMB'].v['Flags2'] = @flags2
        pkt['Payload']['SMB'].v['ErrorClass'] = 0xc0000225 # NT_STATUS_NOT_FOUND
        c.put(pkt.to_s)
    end
  end

  # Internal
  def smb_cmd_trans_query_file_info_standard(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '').strip
    file = Rex::Text.to_unicode(@exe_file)

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 2
    pkt['Payload'].v['DataCountTotal'] = 8
    pkt['Payload'].v['ParamCount'] = 2
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 8
    pkt['Payload'].v['DataOffset'] = 60
    pkt['Payload'].v['Payload'] =
    "\x00" + # Padding
    # QUERY_FILE Parameters
    "\x00\x00" + # EA Error Offset
    "\x00\x00" + # Padding
    # QUERY_FILE_INFO Data
    "\x95\x1c\x02\x00\x00\x00\x00\x00"
    # Index number (can be random?) Or Allocation Size?

    my_pkt = pkt.to_s
    original_length = my_pkt[2, 2].unpack("n").first
    original_length = original_length + 8
    my_pkt[2, 2] = [original_length].pack("n")
    new_length = my_pkt[2, 2].unpack("n").first
    #c.put(my_pkt)
    c.put(pkt.to_s)
  end

  # Standard
  def smb_cmd_trans_query_path_info_standard(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '').strip
    file = Rex::Text.to_unicode(@exe_file)
    length = pkt['Payload'].v['SetupData'].length
    dprint("[query_info_standard] Payload length: " + length.to_s)
    dprint("[query_info_standard] File name length: " + @exe_file.length.to_s)

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    if length >= @exe_file.length
        # Its asking for the file
        attrib1 = "\x20\x00\x00\x00" # File attributes => file
        attrib2 = "\x00" # IsFile
        dprint("[query_info_standard] Sending file response: " + file + " with length: " + @exe.length.to_s)
    else
        # if QUERY_PATH_INFO_PARAMETERS doesn't include a file name,
        # return a Directory answer
        attrib1 = "\x10\x00\x00\x00" # File attributes => directory
        attrib2 = "\x01" # IsDir
        dprint("[query_info_standard] Sending directory response")
    end

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 2
    pkt['Payload'].v['DataCountTotal'] = 24
    pkt['Payload'].v['ParamCount'] = 2
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 24
    pkt['Payload'].v['DataOffset'] = 60
    pkt['Payload'].v['Payload'] =
      "\x00" + # Padding
      # QUERY_PATH_INFO Parameters
      "\x00\x00" + # EA Error Offset
      "\x00\x00" + # Padding
      # QUERY_PATH_INFO Data
      "\x00\x00\x10\x00\x00\x00\x00\x00" + # Allocation Size = 1048576 || 1Mb
      [@exe.length].pack("V") + "\x00\x00\x00\x00" + # End Of File
      "\x01\x00\x00\x00" + # Link Count
      "\x00" + # Delete Pending
      attrib2 +
      "\x00\x00" # Unknown
    c.put(pkt.to_s)
  end

  def smb_cmd_trans_query_path_info_basic(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = Rex::Text.to_unicode(pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '\\').strip)
    file = Rex::Text.to_unicode(@exe_file)
    dprint("[query_info_basic] Payload is: " + payload + " with length: " + @exe.length.to_s)

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    if payload =~ /#{file}/i
        attrib = "\x20\x00\x00\x00" # File attributes => file
        dprint("[query_info_basic] Sending file response: " + file + " with length: " + @exe.length.to_s)
    else
      # if QUERY_PATH_INFO_PARAMETERS doesn't include a file name,
      # return a Directory answer
      attrib = "\x10\x00\x00\x00" # File attributes => directory
      dprint("[query_info_basic] Sending directory response")
    end

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 2
    pkt['Payload'].v['DataCountTotal'] = 40
    pkt['Payload'].v['ParamCount'] = 2
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 40
    pkt['Payload'].v['DataOffset'] = 60
    pkt['Payload'].v['Payload'] =
      "\x00" + # Padding
      # QUERY_PATH_INFO Parameters
      "\x00\x00" + # EA Error Offset
      "\x00\x00" + # Padding
      #QUERY_PATH_INFO Data
      [@lo, @hi].pack("VV") + # Created
      [@lo, @hi].pack("VV") + # Last Access
      [@lo, @hi].pack("VV") + # Last Write
      [@lo, @hi].pack("VV") + # Change
      attrib +
      "\x00\x00\x00\x00" # Unknown
    c.put(pkt.to_s)
  end

  def smb_cmd_trans_find_first2(c, buff)

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    file_name = Rex::Text.to_unicode(@exe_file)
    dprint("Asking for " + file_name)

    # For some reason filename is out by <x>4 (14/94?)
    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 10
    pkt['Payload'].v['DataCountTotal'] = 14 + file_name.length
    pkt['Payload'].v['ParamCount'] = 10
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 14 + file_name.length
    pkt['Payload'].v['DataOffset'] = 68
    pkt['Payload'].v['Payload'] =
      "\x00" + # Padding
      # FIND_FIRST2 Parameters
      "\xfd\xff" + # Search ID
      "\x01\x00" + # Search count
      "\x01\x00" + # End Of Search
      "\x00\x00" + # EA Error Offset
      "\x00\x00" + # Last Name Offset
      "\x00\x00" + # Padding
      #QUERY_PATH_INFO Data
      [14 + file_name.length].pack("V") + # Next Entry Offset
      "\x00\x00\x00\x00" + # File Index
      [file_name.length].pack("V") + # File Name Len
      file_name +
      "\x00\x00" # Padding

    c.put(pkt.to_s)
  end

end # End Class
end # End SMB
end # End Proto
end # End Rex
