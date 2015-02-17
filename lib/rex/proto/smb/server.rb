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

##
#
# SMB Server class
#
##
class Server

# Read Write
  attr_accessor :listen_port, :listen_host, :context
  attr_accessor :listener
  attr_accessor :process_id, :name, :ip, :port, :data, :file_id, :dir_id
  attr_accessor :user_id, :tree_id, :multiplex_id

# Read Only
  attr_reader :hi, :lo

  CONST = Rex::Proto::SMB::Constants
  UTILS = Rex::Proto::SMB::Utils

  #
  # Setup State
  #
  def initialize(port, listen_host, context = {})
    self.listen_host  = listen_host
    self.listen_port  = port
    self.context      = context
    self.listener     = nil
    self.multiplex_id = rand(0xffff)
    self.process_id   = rand(0xffff)
    self.file_id      = 0xdead
    self.dir_id       = 0xbeef
    @state = {}
  end

  #
  # SMB server.
  #
  def alias
    super || "SMBServer"
  end

  #
  # Debugging
  #
  def dprint(msg)
    #$stdout.puts "#{msg}"
    dlog("#{msg}", 'rex', LEV_3)
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
  # Closes the connection to the remote server.
  #
  def close
    if (self.listener)
      self.listener.stop
      self.listener.close
    end
    
    self.listener = nil
  end
    
  #
  # Terminates the monitor thread and turns off the listener.
  #
  def stop
    close
  end

  #
  # Returns whether or not the conn is valid.
  #
  def conn?
    listener != nil
  end

  #
  # Waits for the SMB service to terminate
  #
  def wait
    self.listener.wait if self.listener
  end

  ##
  #
  # Register globals
  #
  # @param unc [String] The UNC path to expose by the server:
  #         ie. \\\\SRVHOST\\share\\path\\to\\myfile.extension
  # @param contents [String] The contents of the file to be served
  #         (usually the MSF payload)
  # @param file_name [String] The name of the file served:
  #         ie. myfile.extension
  # @param hi [Integer] Current unix time in 64 bit SMB format
  # @param lo [Integer] Current unix time in 64 bit SMB format
  # @return [void]
  #
  ##
  def register(unc, contents, file_name, hi, lo)
      @unc = unc
      @file_name = file_name.gsub(/\//, '\\').split('\\').last
      # All but last
      @path_name = file_name.split('/')[0..-2].join('\\').gsub(/\/\/\/\//, '\\').gsub(/\\\\/, '\\')
      @hi = hi
      @lo = lo
      @exe = contents
      @flags2 = 0xc807 # e807 or c807 or c001
  end

protected

  #
  # Handler to register new connections from the client
  #
  def on_client_connect(client)
    #dprint("New SMB connection from #{client.peerhost}:#{client.peerport}")
    smb_conn(client)
  end

  #
  # Handler to receieve and dispatch data received from the client
  #
  def on_client_data(client)
    #dprint("New data from #{client.peerhost}:#{client.peerport}")
    smb_recv(client)
    true
  end

  #
  # Logs the client state in @state
  #
  def smb_conn(c)
    @state[c] = {:name => "#{c.peerhost}:#{c.peerport}",
                 :ip => c.peerhost, :port => c.peerport}
  end

  #
  # Deletes the client state on disconnect
  #
  def smb_stop(c)
    @state.delete(c)
  end

  #
  # Primary function that receives data from the client and sends it to the
  # dispatcher
  #
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

      #dprint("NetBIOS request from #{smb[:name]} #{pkt_nbs.v['Type']} #{pkt_nbs.v['Flags']} #{buff.inspect}")

      # Check for a NetBIOS name request
      if (pkt_nbs.v['Type'] == 0x81)
        # Accept any name they happen to send

        host_dst = UTILS.nbname_decode(pkt_nbs.v['Payload'][1,32]).gsub(/[\x00\x20]+$/n, '')
        host_src = UTILS.nbname_decode(pkt_nbs.v['Payload'][35,32]).gsub(/[\x00\x20]+$/n, '')

        smb[:nbdst] = host_dst
        smb[:nbsrc] = host_src

        #dprint("NetBIOS session request from #{smb[:name]} (asking for #{host_dst} from #{host_src})")
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

  #
  # Function to retrieve the SMB state and record the following values used
  # elsewhere in this class:
  #  ProcessID
  #  UserID
  #  TreeID
  #  MultiplexID
  #
  def smb_set_defaults(c, pkt)
    smb = @state[c]
    pkt['Payload']['SMB'].v['ProcessID'] = self.process_id.to_i
    pkt['Payload']['SMB'].v['UserID'] = self.user_id.to_i
    pkt['Payload']['SMB'].v['TreeID'] = self.tree_id.to_i
    pkt['Payload']['SMB'].v['MultiplexID'] = self.multiplex_id.to_i
  end

  #
  # Returns an smb error packet
  #
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

  #
  # Main dispatcher function
  # Takes the client data and performs a case switch
  # on the command (e.g. Negotiate, Session Setup, Read file, etc.)
  #
  def smb_cmd_dispatch(cmd, c, buff)
    smb = @state[c]
    dprint("Received command #{cmd.to_s(16)} from #{smb[:name]}")

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
        if wordcount == 0x0D # Share Security Mode sessions
          dprint("[smb_cmd_session_setup] wordcount is: #{wordcount.to_s}")
          smb_cmd_session_setup(c, buff)
        #elsif wordcount == 0x0C # Also Share Security Mode sessions with NTLMSSP
        #  dprint("[smb_cmd_ntlmssp_session_setup] wordcount is: #{wordcount.to_s}")
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
        dprint("[smb_cmd_read]")
        smb_cmd_read(c, buff)
      when CONST::SMB_COM_CLOSE
        smb_cmd_close(c, buff)
      else
        dprint("SMB Capture - Ignoring request from #{smb[:name]} - #{smb[:ip]} (#{cmd})")
        smb_error(cmd, c, CONST::SMB_STATUS_SUCCESS)
    end
  end

  #
  # Responds to a client CLOSE request
  #
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

  #
  # Responds to client TRANSACTION2 requests and dispatches the request off to
  # other functions dependent on what the sub_command is. Commands supported
  # include:
  #  QUERY_FILE_INFO (Basic, Standard and Internal)
  #  QUERY_PATH_INFO (Basic and Standard)
  #
  def smb_cmd_trans(c, buff)
    # Client socket is c
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    sub_command = pkt['Payload'].v['SetupData'].unpack("v").first
    dprint("Command is: #{sub_command.to_s}")
    ar = Rex::Text.to_hex(buff, '').to_s
    mdc = ar[86..89]

    case sub_command
      when 0x24 # QUERY_FILE_INFO
        dprint("[query_file_info_24]")
        # path info works here
        smb_cmd_trans_query_path_info_standard(c, buff)
      when 0x7 # QUERY_FILE_INFO
        dprint("[query_file_info_7]")
        loi = ar[148..151]
        dprint("LOI is: #{loi}")
        case loi
         when 'ed03' # Query Path Standard Info
          smb_cmd_trans_query_path_info_standard(c, buff)
         else
          smb_cmd_trans_query_file_info_standard(c, buff)
         end
      when 0x5 # QUERY_PATH_INFO
       dprint("[query_path_info]")
       dprint("MDC is: #{mdc}")
       loi = ar[144..147]
       dprint("LOI is: #{loi}")
       case mdc # MAX DATA COUNT
        when '2800'
          # Basic is MDC = 40 / 2800 hex
          case loi
           when '0101' # Query File Basic Info
            dprint("[query_file_info_basic]")
            smb_cmd_trans_query_file_info_basic(c, buff)
           else
            dprint("[query_path_info_basic]")
            smb_cmd_trans_query_path_info_basic(c, buff)
           end
        when '1800', '0201'
          # Standard is MDC = 24 / 1800 hex or 258 / 0201 hex
          dprint("[query_path_info_standard]")
          smb_cmd_trans_query_path_info_standard(c, buff)
        when '0800'
          # Internal File info is MDC = 8 / 0800 hex
          dprint("[query_file_info_basic]")
          smb_cmd_trans_query_file_info_standard(c, buff)
        when '3800'
          # Query file network open info
          dprint("[query_file_info_network]")
          smb_cmd_trans_query_file_info_network(c, buff)
        else
          dprint("Unknown MDC - Sending to [query_path_info_standard]: #{mdc.to_s}")
          smb_cmd_trans_query_path_info_standard(c, buff)
        end
      when 0x1 # FIND_FIRST2
        dprint("find_first2")
        loi = ar[156..159]
        dprint("MDC is: #{mdc}")
        dprint("LOI is: #{loi}")
        case loi
          when '0301' # Find File Names Info # 259
            smb_cmd_trans_find_first2_file(c, buff)
          when '0401' # Find File Both Directory Info # 260
            smb_cmd_trans_find_first2(c, buff)
          when '0201' # Find File Full Directory Info # 258
            smb_cmd_trans_find_first2_full(c, buff)
          else
            smb_cmd_trans_find_first2(c, buff)
          end
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

  #
  # Negotiates a SHARE session with the client
  #
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
    #pkt['Payload'].v['MaxBuff'] = 16644
    pkt['Payload'].v['MaxBuff'] = 4356
    pkt['Payload'].v['MaxRaw'] = 65536
    pkt['Payload'].v['SystemTimeLow'] = @lo
    pkt['Payload'].v['SystemTimeHigh'] = @hi
    pkt['Payload'].v['ServerTimeZone'] = 0x0
    pkt['Payload'].v['SessionKey'] = 0
    #pkt['Payload'].v['Capabilities'] = 0x8080f3fd NTLMSSP capabilities
    #pkt['Payload'].v['Capabilities'] = 0xd4
    pkt['Payload'].v['Capabilities'] = 0x0080f3fd
    pkt['Payload'].v['KeyLength'] = 8
    pkt['Payload'].v['Payload'] = Rex::Text.rand_text_hex(8)

    c.put(pkt.to_s)
  end

  #
  # Negotiates an NTLMSSP Session with the client
  # Currently unimplemented
  #
  def smb_cmd_ntlmssp_session_setup(c, buff)
    # TODO: Havent implemented ntlmssp yet
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
    #pkt['Payload'].v['Action'] = 0 # Not Logged in as GUEST
    pkt['Payload'].v['Action'] = 0x1 # Logged in as GUEST
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
    #tree_connect_response << [0xff].pack("C") # Access Mask All Flags On
    #tree_connect_response << [0x01].pack("C")
    #tree_connect_response << [0x1f].pack("C")
    #tree_connect_response << [0xff].pack("C")
    tree_connect_response << [0xa9].pack("C") # Access Mask for just Read and Exec
    tree_connect_response << [0x00].pack("C")
    tree_connect_response << [0x12].pack("C")
    tree_connect_response << [0x00].pack("C")
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

  #
  # Sets up an SMB session in response to a SESSION_SETUP_ANDX request
  #
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
    #tree_connect_response << [0xff].pack("C") # Access Mask All Flags On
    #tree_connect_response << [0x01].pack("C")
    #tree_connect_response << [0x1f].pack("C")
    #tree_connect_response << [0xff].pack("C")
    tree_connect_response << [0xa9].pack("C") # Access Mask for just Read and Exec
    tree_connect_response << [0x00].pack("C")
    tree_connect_response << [0x12].pack("C")
    tree_connect_response << [0x00].pack("C")
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

  #
  # Responds to a client NT_CREATE_ANDX request
  #
  def smb_cmd_create(c, buff)
    pkt = CONST::SMB_CREATE_PKT.make_struct
    pkt.from_s(buff)

    # Tries to do CREATE and X
    payload = pkt['Payload'].v['Payload'].gsub(/\x00/, '').gsub(/.*\\/, '\\').chomp.strip.split('\\').last
    dprint("[smb_cmd_create] Payload is: #{payload}")
    file = @file_name
    path = @path_name

    if payload.nil?
      payload = file
    end

    if payload.length.to_s.eql?('1') or payload.eql?(path)
      dprint("[smb_cmd_create] Sending directory response")
      fid = self.dir_id.to_i
      attribs = 0x10 # Ordinary Dir
      eof = 0
      isdir = 1
    else
      dprint("[smb_cmd_create] Sending file response")
      fid = self.file_id.to_i
      attribs = 0x80 # File Attributes
      eof = @exe.length
      isdir = 0
    end

    pkt = CONST::SMB_CREATE_RES_PKT.make_struct
    smb_set_defaults(c, pkt)
    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 42
    pkt['Payload'].v['AndX'] = 0xff # no further commands
    pkt['Payload'].v['OpLock'] = 0x3 # Grant Oplock on File
    pkt['Payload'].v['FileID'] = fid
    pkt['Payload'].v['Action'] = 0x1 # The file existed and was opened
    pkt['Payload'].v['CreateTimeLow'] = @lo
    pkt['Payload'].v['CreateTimeHigh'] = @hi
    pkt['Payload'].v['AccessTimeLow'] = @lo
    pkt['Payload'].v['AccessTimeHigh'] = @hi
    pkt['Payload'].v['WriteTimeLow'] = @lo
    pkt['Payload'].v['WriteTimeHigh'] = @hi
    pkt['Payload'].v['ChangeTimeLow'] = @lo
    pkt['Payload'].v['ChangeTimeHigh'] = @hi
    #pkt['Payload'].v['Attributes'] = 0x20 # Not an archive
    #pkt['Payload'].v['AllocLow'] = 1048576 # 1Mb
    pkt['Payload'].v['Attributes'] = attribs
    pkt['Payload'].v['AllocLow'] = 0x100000
    pkt['Payload'].v['AllocHigh'] = 0
    pkt['Payload'].v['EOFLow'] = eof
    pkt['Payload'].v['EOFHigh'] = 0
    pkt['Payload'].v['FileType'] = 0
    pkt['Payload'].v['IPCState'] = 0x7
    pkt['Payload'].v['IsDirectory'] = isdir

    # As above, if payload is a file or "\" send found response
    if (payload.downcase.eql?(file.downcase)) or payload.length.to_s.eql?('1') or payload.eql?(path)
      dprint("[smb_cmd_create] Sending response")
      connect_response = ""
      # GUID
      connect_response << ([0].pack("C") * 16)
      # File ID
      connect_response << ([0].pack("C") * 6)
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
      # Otherwise send not found
      dprint("[smb_cmd_create] Sending NOT FOUND")
      pkt = CONST::SMB_CREATE_RES_PKT.make_struct
      smb_set_defaults(c, pkt)
      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_CREATE_ANDX
      pkt['Payload']['SMB'].v['ErrorClass'] = 0xC0000034 # OBJECT_NAME_NOT_FOUND
      pkt['Payload']['SMB'].v['Flags1'] = 0x88
      pkt['Payload']['SMB'].v['Flags2'] = @flags2
      c.put(pkt.to_s)
    end
  end

  #
  # Responds to a client READ_ANDX request
  # This function sends chunks of the payload to the client
  # by reading the offset and length requested by the client
  # and sending the appropriate chunk of the payload
  #
  def smb_cmd_read(c, buff)
    pkt = CONST::SMB_READ_PKT.make_struct
    pkt.from_s(buff)

    offset = pkt['Payload'].v['Offset']
    length = pkt['Payload'].v['MaxCountLow']

    pkt = CONST::SMB_READ_RES_PKT.make_struct
    smb_set_defaults(c, pkt)
    dprint("Sending File! Offset: #{offset.to_s} Length: #{length.to_s}")

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

  #
  # Responds to QUERY_FILE_INFO (Network) requests
  #
  def smb_cmd_trans_query_file_info_network(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '').chomp.strip
    dprint("[smb_cmd_trans_query_file_info_network] Payload length: #{payload.length.to_s}")
    dprint("[smb_cmd_trans_query_file_info_network] Payload is : #{payload.to_s}")

    if payload.length.to_s.eql?('4')
      attrib = "\x10\x00\x00\x00" # File attributes => directory
    else
      attrib = "\x80\x00\x00\x00" # File attributes => normal file
    end

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 2
    pkt['Payload'].v['DataCountTotal'] = 56
    pkt['Payload'].v['ParamCount'] = 2
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 56
    pkt['Payload'].v['DataOffset'] = 60
    pkt['Payload'].v['Payload'] =
      "\x00" + # Padding
      # QUERY_PATH_INFO Parameters
      "\x00\x00" + # EA Error Offset
      "\x00\x00" + # Padding
      # QUERY_PATH_INFO Data
      [@lo, @hi].pack("VV") + # Created
      [@lo, @hi].pack("VV") + # Last Access
      [@lo, @hi].pack("VV") + # Last Write
      [@lo, @hi].pack("VV") + # Change
      "\x00\x00\x10\x00\x00\x00\x00\x00" + # Allocation Size = 1048576 || 1Mb
      [@exe.length].pack("V") + "\x00\x00\x00\x00" + # End Of File
      attrib +
      "\x00\x00\x00\x00" # Unknown

    my_pkt = pkt.to_s
    original_length = my_pkt[2, 2].unpack("n").first
    original_length = original_length + 24
    my_pkt[2, 2] = [original_length].pack("n")
    new_length = my_pkt[2, 2].unpack("n").first
    c.put(pkt.to_s)
  end

  #
  # Responds to QUERY_FILE_INFO (Standard) requests
  #
  def smb_cmd_trans_query_file_info_standard(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '').chomp.strip
    file = Rex::Text.to_unicode(@file_name)

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

    my_pkt = pkt.to_s
    original_length = my_pkt[2, 2].unpack("n").first
    original_length = original_length + 8
    my_pkt[2, 2] = [original_length].pack("n")
    new_length = my_pkt[2, 2].unpack("n").first
    c.put(pkt.to_s)
  end

  #
  # Responds to QUERY_PATH_INFO (Standard) requests
  #
  def smb_cmd_trans_query_path_info_standard(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '').chomp.strip
    ar = Rex::Text.to_hex(buff, '').to_s
    fid = ar[146..147] + ar[144..145]
    dprint("[smb_cmd_trans_query_path_info_standard] fid is : #{fid.hex}, file_id is : " + self.file_id.to_s)
    dprint("[smb_cmd_trans_query_path_info_standard] Payload length: #{payload.length.to_s}")

    # If FileID matches or matches file, send file response 
    if ( fid.hex.eql?(self.file_id.to_i) or payload.length.eql?(@file_name.length) )
        attrib2 = "\x00" # IsFile
        dprint("[smb_cmd_trans_query_path_info_standard] Sending file response")
    else
        # Otherwise return a Directory answer
        attrib2 = "\x01" # IsDir
        dprint("[smb_cmd_trans_query_path_info_standard] Sending directory response")
    end

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

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

  #
  # Responds to QUERY_FILE_INFO (Basic) requests
  #
  def smb_cmd_trans_query_file_info_basic(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '\\').chomp.strip
    file = @file_name
    path = @path_name
    dprint("[smb_cmd_trans_query_file_info_basic] Payload is: #{payload} with length: #{@exe.length.to_s}")
    dprint("[smb_cmd_trans_query_file_info_basic] Payload length: #{payload.length.to_s}")
    dprint("[smb_cmd_trans_query_file_info_basic] File name length: #{@file_name.length.to_s}")

    ar = Rex::Text.to_hex(buff, '').to_s
    dprint("[smb_cmd_trans_query_file_info_basic] ar is : #{ar}")
    fid = ar[146..147] + ar[144..145]
    dprint("[smb_cmd_trans_query_file_info_basic] fid is : #{fid.hex}, file_id is : " + self.file_id.to_s)
    if ( fid.hex.eql?(self.file_id.to_i) )
      dprint("File match")
    end
    if ( fid.hex.eql?(self.dir_id.to_i) )
      dprint("Dir match")
    end

    if path.nil? || path == 0
      dprint("[smb_cmd_trans_query_file_info_basic] Path is empty")
      path = '\\'
    else
      dprint("[smb_cmd_trans_query_file_info_basic] Path is: #{path}")
    end

    if path.nil? || path == 0
      dprint("[smb_cmd_trans_query_file_info_basic] Path is empty")
      path = '\\'
    else
      dprint("[smb_cmd_trans_query_file_info_basic] Path is: #{path}")
    end

    begin
      fileext = file.split('.').last
    rescue
      fileext = file
    end

    begin
      payext = payload.split('.').last
    rescue
      payext = payload
    end

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    # If payload contains our file extension, send file response
    if payext and payext.downcase.eql?(fileext.downcase)
      #attrib = "\x20\x00\x00\x00" # File attributes => archive: file has been modified
      attrib = "\x80\x00\x00\x00" # File attributes => file
      dprint("[smb_cmd_trans_query_file_info_basic] Sending file response: #{file} with length: #{@exe.length.to_s}")
    elsif payload.length.to_s.eql?('1') or payload.eql?(path)
      # if QUERY_PATH_INFO_PARAMETERS doesn't include a file name,
      # return a Directory answer
      attrib = "\x10\x00\x00\x00" # File attributes => directory
      dprint("[smb_cmd_trans_query_file_info_basic] Sending directory response")
    end

    if (payext and payext.downcase.eql?(fileext.downcase)) or payload.length.to_s.eql?('1') or payload.length.to_s.eql?('4') or payload.eql?(path)
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
    else
      dprint("[smb_cmd_trans_query_file_info_basic] Sending NOT FOUND")
      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
      pkt['Payload']['SMB'].v['ErrorClass'] = 0xC0000034 # OBJECT_NAME_NOT_FOUND
      pkt['Payload']['SMB'].v['Flags1'] = 0x88
      pkt['Payload']['SMB'].v['Flags2'] = @flags2
      c.put(pkt.to_s)
    end
  end

  #
  # Responds to QUERY_PATH_INFO (Basic) requests
  #
  def smb_cmd_trans_query_path_info_basic(c, buff)
    pkt = CONST::SMB_TRANS2_PKT.make_struct
    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '\\').chomp.strip.split('\\').last
    file = @file_name

    dprint("[smb_cmd_trans_query_path_info_basic] Payload is: #{payload}")
    dprint("[smb_cmd_trans_query_path_info_basic] Payload length: #{payload.length.to_s}")
    dprint("[smb_cmd_trans_query_path_info_basic] File name : #{file.to_s}")
    dprint("[smb_cmd_trans_query_path_info_basic] File name length: #{file.length.to_s}")

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    # If payload contains our file, send a file response
    # For MS13-071, payload is an empty unicode request (4 bytes)
    if payload.downcase.eql?(file.downcase) or payload.length.to_s.eql?('4')
      if payload.length.to_s.eql?('4')
        attrib = "\x10\x00\x00\x00" # File attributes => directory 
        dprint("[smb_cmd_trans_query_path_info_basic] Sending directory response")
        #attrib = "\x20\x00\x00\x00" # File attributes => archive: file has been modified
      else
        attrib = "\x80\x00\x00\x00" # File attributes => file
        dprint("[smb_cmd_trans_query_path_info_basic] Sending file response")
      end
    else
      if payload.downcase.include?(file.downcase)
        attrib = "\x80\x00\x00\x00" # File attributes => file
        dprint("[smb_cmd_trans_query_path_info_basic] Sending file response")
      else
        # QUERY_PATH_INFO_PARAMETERS doesn't include a file name, return a Directory answer
        attrib = "\x10\x00\x00\x00" # File attributes => directory
        dprint("[smb_cmd_trans_query_path_info_basic] Sending directory response")
      end
    end

    # If payload contains our file, send the response 
    if payload.downcase.eql?(file.downcase) or payload.length.to_s.eql?('4') or payload.downcase.include?(file.downcase)
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
    else
      # Else send not found
      dprint("[smb_cmd_trans_query_path_info_basic] Sending NOT FOUND")
      pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
      pkt['Payload']['SMB'].v['ErrorClass'] = 0xC0000034 # OBJECT_NAME_NOT_FOUND
      pkt['Payload']['SMB'].v['Flags1'] = 0x88
      pkt['Payload']['SMB'].v['Flags2'] = @flags2
      c.put(pkt.to_s)
    end
  end

  #
  # Responds to FIND_FIRST2 requests
  # Command: Find File Both Directory Info
  #
  def smb_cmd_trans_find_first2(c, buff)
    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '\\').chomp.strip
    file = @file_name
    file_name = Rex::Text.to_unicode(@file_name)
    path = Rex::Text.to_unicode(@path_name)

    dprint("[smb_cmd_trans_find_first2] Payload is: #{payload}")
    dprint("[smb_cmd_trans_find_first2] Payload length: #{payload.length.to_s}")

    ar = Rex::Text.to_hex(buff, '').to_s
    dprint("[smb_cmd_trans_find_first2] ar is : #{ar}")
    fid = ar[146..147] + ar[144..145]
    dprint("[smb_cmd_trans_find_first2] fid is : #{fid.hex}, file_id is : " + self.file_id.to_s)
    if ( fid.hex.eql?(self.file_id.to_i) )
      dprint("File match")
    end
    if ( fid.hex.eql?(self.dir_id.to_i) )
      dprint("Dir match")
    end

    if path.nil? || path == 0
      dprint("[smb_cmd_trans_find_first2] Path is empty")
      path = '\\'
    else
      dprint("[smb_cmd_trans_find_first2] Path is: #{path}")
    end

    begin
      fileext = file.split('.').last
    rescue
      fileext = file
    end

    begin
      payext = payload.split('.').last
    rescue
      payext = payload
    end

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    if (payext and payext.downcase.eql?(fileext.downcase)) or payload.length.to_s.eql?('4')
      dprint("[smb_cmd_trans_find_first2] Sending file response #{file}")
      data = file_name
      length = [@exe.length].pack("V")
      ea = "\x00\x00"
      alloc = "\x00\x00\x10\x00\x00\x00\x00\x00" # Allocation Size = 1048576 || 1Mb
      attrib = "\x80\x00\x00\x00" # File
      search = "\x01\x00"
    else
      dprint("[smb_cmd_trans_find_first2] Sending directory response #{path}")
      data = path
      length = "\x00\x00\x00\x00" 
      ea = "\x21\x00"
      alloc = "\x00\x00\x00\x00\x00\x00\x00\x00" # 0Mb
      attrib = "\x10\x00\x00\x00" # Dir
      pkt['Payload'].v['SetupCount'] = 0
      search = "\x00\x01"
    end

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 10
    pkt['Payload'].v['DataCountTotal'] = 94 + data.length
    pkt['Payload'].v['ParamCount'] = 10
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 94 + data.length
    pkt['Payload'].v['DataOffset'] = 68
    pkt['Payload'].v['Payload'] =
     "\x00" + # Padding
     # FIND_FIRST2 Parameters
     "\xfd\xff" + # Search ID
     search + # Search count
     search + # End Of Search
     ea + # EA Error Offset
     "\x00\x00" + # Last Name Offset
     "\x00\x00" + # Padding
     #QUERY_PATH_INFO Data
     [94 + data.length].pack("V") + # Next Entry Offset
     "\x00\x00\x00\x00" + # File Index
     [@lo, @hi].pack("VV") + # Created
     [@lo, @hi].pack("VV") + # Last Access
     [@lo, @hi].pack("VV") + # Last Write
     [@lo, @hi].pack("VV") + # Change
     length + "\x00\x00\x00\x00" + # End Of File
     alloc + 
     attrib + 
     [data.length].pack("V") + # File name len
     "\x00\x00\x00\x00" + # EA List Length
     "\x00" + # Short file length
     "\x00" + # Reserved
     ("\x00" * 24) +
    data 
    c.put(pkt.to_s)
  end

  #
  # Responds to FIND_FIRST2 requests
  # Command: Find File Names Info
  #
  def smb_cmd_trans_find_first2_file(c, buff)
    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '\\').chomp.strip.split('\\').last
    file = @file_name
    file_name = Rex::Text.to_unicode(@file_name)
    path = Rex::Text.to_unicode(@path_name)
    dprint("[smb_cmd_trans_find_first2_file] Payload is: #{payload}")
    dprint("[smb_cmd_trans_find_first2_file] Payload length: #{payload.length.to_s}")

    ar = Rex::Text.to_hex(buff, '').to_s
    dprint("[smb_cmd_trans_find_first2_file] ar is : #{ar}")
    fid = ar[146..147] + ar[144..145]
    dprint("[smb_cmd_trans_find_first2_file] fid is : #{fid.hex}, file_id is : " + self.file_id.to_s)
    if ( fid.hex.eql?(self.file_id.to_i) )
      dprint("File match")
    end
    if ( fid.hex.eql?(self.dir_id.to_i) )
      dprint("Dir match")
    end

    if path.nil? || path == 0
      dprint("[smb_cmd_trans_find_first2_file] Path is empty")
      path = '\\'
    else
      dprint("[smb_cmd_trans_find_first2_file] Path is: #{path}")
    end

    begin
      fileext = file.split('.').last
    rescue
      fileext = file
    end

    begin
      payext = payload.split('.').last
    rescue
      payext = payload
    end

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    if (payext and payext.downcase.eql?(fileext.downcase)) or payload.length.to_s.eql?('4')
      dprint("[smb_cmd_trans_find_first2_file] Sending file response #{file}")
      data = file_name
    else
      dprint("[smb_cmd_trans_find_first2_file] Sending directory response #{path}")
      data = path
    end

    # If its asking for a file, return file
    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 10
    pkt['Payload'].v['DataCountTotal'] = 14 + data.length
    pkt['Payload'].v['ParamCount'] = 10
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 14 + data.length
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
      # QUERY_PATH_INFO Data
      [14 + data.length].pack("V") + # Next Entry Offset
      "\x00\x00\x00\x00" + # File Index
      [data.length].pack("V") + # File Name Len
      data +
      "\x00\x00" # Padding
    c.put(pkt.to_s)
 end

  #
  # Responds to FIND_FIRST2 requests
  # Command: Find File Full Directory Info
  #
  def smb_cmd_trans_find_first2_full(c, buff)
    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    pkt.from_s(buff)

    payload = pkt['Payload'].v['SetupData'].gsub(/\x00/, '').gsub(/.*\\/, '\\').chomp.strip
    file = @file_name
    file_name = Rex::Text.to_unicode(@file_name)
    path = Rex::Text.to_unicode(@path_name)

    dprint("[smb_cmd_trans_find_first2_full] Payload is: #{payload}")
    dprint("[smb_cmd_trans_find_first2_full] Payload length: #{payload.length.to_s}")

    ar = Rex::Text.to_hex(buff, '').to_s
    dprint("[smb_cmd_trans_find_first2_full] ar is : #{ar}")
    fid = ar[146..147] + ar[144..145]
    dprint("[smb_cmd_trans_find_first2_full] fid is : #{fid.hex}, file_id is : " + self.file_id.to_s)
    if ( fid.hex.eql?(self.file_id.to_i) )
      dprint("File match")
    end
    if ( fid.hex.eql?(self.dir_id.to_i) )
      dprint("Dir match")
    end

    if path.nil? || path == 0
      dprint("[smb_cmd_trans_find_first2_full] Path is empty")
      path = '\\'
    else
      dprint("[smb_cmd_trans_find_first2_full] Path is: #{path}")
    end

    begin
      fileext = file.split('.').last
    rescue
      fileext = file
    end

    begin
      payext = payload.split('.').last
    rescue
      payext = payload
    end

    pkt = CONST::SMB_TRANS_RES_PKT.make_struct
    smb_set_defaults(c, pkt)

    if (payext and payext.downcase.eql?(fileext.downcase)) or payload.length.to_s.eql?('4')
      dprint("[smb_cmd_trans_find_first2_full] Sending file response #{file}")
      data = file_name
      length = [@exe.length].pack("V")
      ea = "\x00\x00"
      alloc = "\x00\x00\x10\x00\x00\x00\x00\x00" # Allocation Size = 1048576 || 1Mb
      attrib = "\x80\x00\x00\x00" # File
      search = "\x01\x00"
    else
      dprint("[smb_cmd_trans_find_first2_full] Sending directory response #{path}")
      data = path
      length = "\x00\x00\x00\x00" 
      ea = "\x21\x00"
      alloc = "\x00\x00\x00\x00\x00\x00\x00\x00" # 0Mb
      attrib = "\x10\x00\x00\x00" # Dir
      pkt['Payload'].v['SetupCount'] = 0
      search = "\x00\x01"
    end

    pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_TRANSACTION2
    pkt['Payload']['SMB'].v['Flags1'] = 0x88
    pkt['Payload']['SMB'].v['Flags2'] = @flags2
    pkt['Payload']['SMB'].v['WordCount'] = 10
    pkt['Payload'].v['ParamCountTotal'] = 10
    pkt['Payload'].v['DataCountTotal'] = 68 + data.length
    pkt['Payload'].v['ParamCount'] = 10
    pkt['Payload'].v['ParamOffset'] = 56
    pkt['Payload'].v['DataCount'] = 68 + data.length
    pkt['Payload'].v['DataOffset'] = 68
    pkt['Payload'].v['Payload'] =
     "\x00" + # Padding
     # FIND_FIRST2 Parameters
     "\xfd\xff" + # Search ID
     search + # Search count
     search + # End Of Search
     ea + # EA Error Offset
     "\x00\x00" + # Last Name Offset
     "\x00\x00" + # Padding
     # QUERY_PATH_INFO Data
     [68 + data.length].pack("V") + # Next Entry Offset
     "\x00\x00\x00\x00" + # File Index
     [@lo, @hi].pack("VV") + # Created
     [@lo, @hi].pack("VV") + # Last Access
     [@lo, @hi].pack("VV") + # Last Write
     [@lo, @hi].pack("VV") + # Change
     length + "\x00\x00\x00\x00" + # End Of File
     alloc + 
     attrib + 
     [data.length].pack("V") + # File name len
     "\x00\x00\x00\x00" + # EA List Length
     data 
    c.put(pkt.to_s)
 end

end # End Class
end # End SMB
end # End Proto
end # End Rex
