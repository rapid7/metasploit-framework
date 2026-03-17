##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/local/windows_kernel/handle_enum'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Auxiliary::Report
  include Msf::Exploit::Local::WindowsKernel::HandleEnum

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
      OptString.new('EXPORT_CSV', [false, 'Export results to CSV file'])
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

    @pointers = enum_system_handles(session, datastore['MAX_HANDLES'], datastore['TIMEOUT'])

    if @pointers.nil? || @pointers.empty?
      print_error('Failed to enumerate kernel pointers')
      return
    end

    print_good("Enumerated #{@pointers.size} kernel object pointers")

    display_results

    export_results if datastore['EXPORT_CSV']
  end

  def validate_environment
    begin
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
        proc_name = get_process_name(session, pid)
        print_line("    #{proc_name} (PID: #{pid}): #{ptrs.size} ALPC pointers")
      end

      print_line("\n  Sample ALPC kernel addresses:")
      alpc_pointers.first(10).each_with_index do |p, i|
        print_line("    #{i + 1}. Type #{p[:type_index]}: 0x#{p[:address].to_s(16)}")
      end
    end

    print_line("\n" + '=' * 80)
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

    size_str = format_file_size(csv.bytesize)

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
