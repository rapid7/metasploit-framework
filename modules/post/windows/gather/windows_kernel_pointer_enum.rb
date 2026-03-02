##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Kernel Pointer Exposure Enumerator',
        'Description' => %q{
          This module enumerates kernel object pointers exposed via
          NtQuerySystemInformation with SystemExtendedHandleInformation.

          It categorizes exposed pointers by object type and provides
          observational data about kernel address space layout for
          research and educational purposes.
        },
        'License' => MSF_LICENSE,
        'Author' => ['CharlesQuinnDev'],
        'Platform' => 'win',
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptInt.new('MAX_HANDLES', [true, 'Maximum handles to process (0 = unlimited)', 50000]),
      OptInt.new('TIMEOUT', [true, 'Timeout in seconds for enumeration', 30]),
      OptString.new('EXPORT_CSV', [false, 'Export results to CSV file', nil])
    ])
  end

  def run
    print_status('Windows Kernel Pointer Exposure Enumerator')
    print_line('=' * 80)

    unless validate_environment
      print_error('Environment validation failed')
      return
    end

    print_status('Enumerating kernel object pointers...')

    @pointers = enumerate_pointers

    if @pointers.nil? || @pointers.empty?
      print_error('Failed to enumerate kernel pointers')
      return
    end

    print_good("Enumerated #{@pointers.size} kernel object pointers")

    display_results

    export_results if datastore['EXPORT_CSV']
  end

  def validate_environment
    sysinfo = session.sys.config.sysinfo
    @os = sysinfo['OS']
    @arch = sysinfo['Architecture']
    @computer = sysinfo['Computer']

    print_status("Target: #{@computer}")
    print_status("OS: #{@os}")
    print_status("Arch: #{@arch}")
    print_status("User: #{session.sys.config.getuid}")

    unless @arch =~ /x64|64|amd64/i
      print_error('This module only supports x64 systems')
      return false
    end

    true
  rescue StandardError => e
    print_error("Failed to get system info: #{e.message}")
    false
  end

  def enumerate_pointers
    pointers = []
    max_attempts = 5
    attempt = 0
    buffer_size = 1024 * 1024

    begin
      Timeout.timeout(datastore['TIMEOUT']) do
        while attempt < max_attempts
          print_status("Attempt #{attempt + 1}: Trying buffer size #{buffer_size} bytes")

          begin
            buffer = "\x00" * buffer_size
          rescue ArgumentError
            print_error("Failed to allocate buffer of size #{buffer_size}")
            return nil
          end

          result = session.railgun.ntdll.NtQuerySystemInformation(64, buffer, buffer_size, 4)

          if result.nil?
            print_error('NtQuerySystemInformation returned nil')
            return nil
          end

          if result['return'] == 0
            print_good("Success with buffer size #{buffer_size}")
            data = result['SystemInformation']
            break
          elsif result['return'] == 0xC0000004
            if result['ReturnLength'] && result['ReturnLength'] > buffer_size
              buffer_size = result['ReturnLength']
              print_status("Buffer too small, need #{buffer_size} bytes")
            else
              buffer_size *= 2
              print_status("Doubling buffer to #{buffer_size} bytes")
            end
            attempt += 1
          else
            print_error("NtQuerySystemInformation failed: 0x#{result['return'].to_s(16)}")
            return nil
          end
        end

        if attempt >= max_attempts
          print_error("Failed to get valid buffer after #{max_attempts} attempts")
          return nil
        end

        if data.nil? || data.length < 16
          print_error('Invalid response data')
          return nil
        end

        num_handles = data[0, 8].unpack('Q').first
        print_good("System has #{num_handles} total handles")

        max_handles = datastore['MAX_HANDLES']
        if max_handles > 0 && num_handles > max_handles
          print_status("Limiting to #{max_handles} handles")
          num_handles = max_handles
        end

        print_status("Processing #{num_handles} handles...")

        offset = 16
        entry_size = 48

        processed = 0
        kernel_pointers = 0

        num_handles.times do |i|
          entry_offset = offset + (i * entry_size)
          break if entry_offset + entry_size > data.length

          entry = data[entry_offset, entry_size]

          begin
            object_ptr = entry[0, 8].unpack('Q').first
            pid = entry[8, 8].unpack('Q').first
            handle = entry[16, 8].unpack('Q').first
            access = entry[24, 4].unpack('V').first
            type_idx = entry[30, 2].unpack('v').first

            if kernel_address?(object_ptr)
              pointers << {
                address: object_ptr,
                pid: pid,
                handle: handle,
                access: access,
                type_index: type_idx
              }
              kernel_pointers += 1
            end

            processed += 1

            if processed % 10000 == 0
              print_status("  Processed #{processed}/#{num_handles} handles (found #{kernel_pointers} kernel addresses)...")
            end
          rescue StandardError => e
            vprint_error("Error parsing handle #{i}: #{e.message}")
          end
        end

        print_good("Processed #{processed} handles, found #{kernel_pointers} kernel addresses")
      end
    rescue Timeout::Error
      print_error("Enumeration timed out after #{datastore['TIMEOUT']} seconds")
      return nil
    rescue StandardError => e
      print_error("Error during enumeration: #{e.message}")
      return nil
    end

    pointers
  end

  def kernel_address?(addr)
    return false if addr.nil? || addr == 0

    high_bits = (addr >> 48) & 0xFFFF
    high_bits == 0xFFFF
  end

  def display_results
    print_line
    print_line('=' * 80)
    print_line('KERNEL POINTER EXPOSURE RESULTS')
    print_line('=' * 80)

    print_line("\nSUMMARY STATISTICS:")
    print_line("  Total pointers: #{@pointers.size}")

    unique = @pointers.uniq { |p| p[:address] }.size
    print_line("  Unique addresses: #{unique}")

    if @pointers.any?
      min_addr = @pointers.map { |p| p[:address] }.min
      max_addr = @pointers.map { |p| p[:address] }.max
      print_line("  Address range: 0x#{min_addr.to_s(16)} - 0x#{max_addr.to_s(16)}")
    end

    by_type = @pointers.group_by { |p| p[:type_index] }

    print_line("\nOBJECT TYPE DISTRIBUTION:")
    by_type.sort.each do |type, ptrs|
      pct = (ptrs.size.to_f / @pointers.size * 100).round(2)
      type_name = get_type_hint(type)
      print_line("  Type #{type} (#{type_name}): #{ptrs.size} pointers (#{pct}%)")
    end

    alpc_pointers = @pointers.select { |p| (32..48).include?(p[:type_index]) }

    if alpc_pointers.any?
      print_line("\n" + '-' * 80)
      print_line('ALPC OBJECT ANALYSIS (Type Indices 32-48)')
      print_line('-' * 80)

      print_line("  Total ALPC pointers: #{alpc_pointers.size}")

      by_pid = alpc_pointers.group_by { |p| p[:pid] }
      print_line("  Found in #{by_pid.size} processes")

      print_line("\n  Processes with ALPC pointers:")
      by_pid.sort_by { |_, v| -v.size }.first(10).each do |pid, ptrs|
        proc_name = get_process_name(pid)
        print_line("    #{proc_name} (PID: #{pid}): #{ptrs.size} ALPC pointers")
      end

      print_line("\n  Sample ALPC kernel addresses:")
      alpc_pointers.first(10).each_with_index do |p, i|
        print_line("    #{i + 1}. Type #{p[:type_index]}: 0x#{p[:address].to_s(16)}")
      end
    end

    print_line("\n" + '=' * 80)
  end

  def get_type_hint(type_idx)
    hints = {
      7 => 'Process',
      8 => 'Thread',
      16 => 'Key',
      24 => 'File',
      32 => 'ALPC',
      33 => 'ALPC',
      34 => 'ALPC',
      35 => 'ALPC Port',
      36 => 'ALPC Port',
      37 => 'ALPC Port',
      38 => 'ALPC Port',
      39 => 'ALPC Port',
      40 => 'ALPC Port',
      41 => 'ALPC Port',
      42 => 'ALPC Section',
      43 => 'ALPC',
      44 => 'ALPC',
      45 => 'ALPC',
      46 => 'ALPC',
      47 => 'ALPC',
      48 => 'ALPC'
    }
    hints[type_idx] || 'Unknown'
  end

  def get_process_name(pid)
    begin
      session.sys.process.each_process do |p|
        return p['name'] if p['pid'] == pid
      end
    rescue ::StandardError
      nil
    end
    "PID:#{pid}"
  end

  def export_results
    return unless datastore['EXPORT_CSV']

    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    filename = "kernel_pointers_#{timestamp}.csv"

    csv = "PID,TypeIndex,TypeHint,Handle,Access,Address\n"
    @pointers.each do |p|
      type_hint = get_type_hint(p[:type_index])
      csv += "#{p[:pid]},#{p[:type_index]},#{type_hint},0x#{p[:handle].to_s(16)},0x#{p[:access].to_s(8)},0x#{p[:address].to_s(16)}\n"
    end

    csv_size = csv.bytesize
    size_str = if csv_size < 1024
                 "#{csv_size} bytes"
               elsif csv_size < 1024 * 1024
                 "#{(csv_size / 1024.0).round(2)} KB"
               else
                 "#{(csv_size / (1024.0 * 1024.0)).round(2)} MB"
               end

    stored_path = store_loot(
      'windows.kernel.pointers',
      'text/csv',
      session,
      csv,
      filename,
      'Windows Kernel Pointer Enumeration Results'
    )

    print_good("Results exported to: #{stored_path} (#{size_str})")
  end
end
