##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache NiFi Version Scanner',
        'Description' => %q{
          This module identifies Apache NiFi websites and reports their version number.

          Tested against NiFi major releases 1.14.0 - 1.21.0, and 1.11.0-1.13.0
          Also works against NiFi <= 1.13.0, but the module needs to be adjusted:
          set SSL false
          set rport 8080
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die',
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8443),
        OptString.new('TARGETURI', [ true, 'The URI of the Apache NiFi Application', '/nifi/login'])
      ]
    )
    register_advanced_options([
      OptBool.new('SSL', [true, 'Negotiate SSL connection', true])
    ])
  end

  def run_host(ip)
    vprint_status("Checking #{ip}")
    res = send_request_cgi!(
      'uri' => normalize_uri(target_uri.path)
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Respones Code (response code: #{res.code})") unless res.code == 200

    if res.body =~ %r{js/nf/nf-namespace\.js\?([\d.]*)">}
      print_good("Apache NiFi #{Regexp.last_match(1)} found on #{ip}")
    else
      print_bad("Apache NiFi not detected on #{ip}")
    end
  end
end
