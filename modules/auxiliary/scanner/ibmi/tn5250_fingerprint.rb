##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'IBM i (AS/400) TN5250 Signon Fingerprint',
      'Description' => %q{
        This module connects to a TN5250(E) service, completes telnet
        option negotiation, and renders the pre-authentication signon
        panel to fingerprint an IBM i (AS/400) host: system name,
        subsystem, device name, and negotiation-layer metadata such as
        TN5250E support, device type/geometry, NEW-ENVIRON codepage and
        keyboard type, and whether the server offers the IBMRSEED
        encrypted/auto-signon path. This module does not attempt
        authentication, exercise the auto-signon path, or send
        credentials -- it is read-only reconnaissance.
      },
      'Author' => ['aydenb'],
      'License' => MSF_LICENSE,
      'References' => [
        ['URL', 'https://www.rfc-editor.org/rfc/rfc1205'],
        ['URL', 'https://www.rfc-editor.org/rfc/rfc1572'],
        ['URL', 'https://www.rfc-editor.org/rfc/rfc4777']
      ],
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [],
        'SideEffects' => [IOC_IN_LOGS]
      }
    )

    register_options(
      [
        Opt::RPORT(23),
        OptInt.new('TIMEOUT', [true, 'Timeout in seconds for negotiation and each record read', 10])
      ]
    )

    register_advanced_options(
      [
        OptString.new('TERM_TYPE', [true, 'TN5250 terminal type to offer during negotiation', 'IBM-3179-2'])
      ]
    )
  end

  # cp037 (EBCDIC US/Canada) -> ASCII, generated from Ruby's IBM037 codec and
  # cross-checked against a captured IBM i signon panel. Anything outside printable
  # ASCII 0x20-0x7E collapses to a space -- this module reads label text and
  # MOTD banners, not full charsets.
  EBCDIC_CP037 = [
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', '.', '<', '(', '+', '|',
    '&', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', '!', '$', '*', ')', ';', ' ',
    '-', '/', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ',', '%', '_', '>', '?',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', '`', ':', '#', '@', "'", '=', '"',
    ' ', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', '~', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', ' ', ' ', ' ', ' ', ' ', ' ',
    '^', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', '[', ']', ' ', ' ', ' ', ' ',
    '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', ' ', ' ', ' ', ' ', ' ', ' ',
    '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', ' ', ' ', ' ', ' ', ' ', ' ',
    '\\', ' ', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', ' ', ' ', ' ', ' ', ' ', ' ',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', ' ', ' ', ' ', ' ', ' ', ' ',
  ].freeze

  def ebcdic_decode(byte)
    EBCDIC_CP037[byte] || ' '
  end

  WTD_COMMAND = 0x11
  GDS_RECORD_TYPE = "\x12\xa0".b

  def extract_wtd_payload(record_bytes)
    return nil if record_bytes.bytesize < 6
    return nil unless record_bytes.byteslice(2, 2) == GDS_RECORD_TYPE

    bytes = record_bytes.bytes
    esc_idx = nil
    (6...(bytes.length - 1)).each do |i|
      if bytes[i] == 0x04 && bytes[i + 1] == WTD_COMMAND
        esc_idx = i
        break
      end
    end
    return nil if esc_idx.nil?

    # esc_idx = ESC, esc_idx+1 = WTD command, esc_idx+2 = WCC
    record_bytes.byteslice((esc_idx + 3)..-1)
  end

  IAC = 0xff
  WILL = 0xfb
  WONT = 0xfc
  DO = 0xfd
  DONT = 0xfe
  SB = 0xfa
  SE = 0xf0
  EOR_CMD = 0xef

  OPT_BINARY = 0x00
  OPT_TERMTYPE = 0x18
  OPT_EOR = 0x19
  OPT_NEWENV = 0x27

  def terminal_type_is_reply(term_type)
    [IAC, SB, OPT_TERMTYPE, 0x00].pack('C*') + term_type.b + [IAC, SE].pack('C*')
  end

  def new_environ_empty_is_reply
    [IAC, SB, OPT_NEWENV, 0x00, IAC, SE].pack('C*')
  end

  def parse_new_environ_send(payload)
    {
      ibmrseed_offered: payload.include?('IBMRSEED'),
      codepage_offered: payload.include?('CODEPAGE'),
      kbdtype_offered: payload.include?('KBDTYPE')
    }
  end

  class Tn5250ProtocolError < RuntimeError; end

  # Walk a telnet byte stream once and separate negotiation from application
  # data. TCP gives us a byte stream, not framed messages: the server may split
  # one reply across segments or coalesce several (including the start of the
  # Write-To-Display record) into a single read. Parsing the stream rather than
  # treating each socket read as one complete reply is what makes negotiation
  # and record framing reliable against both behaviors.
  #
  # In TN5250E BINARY mode a 0xFF data byte is doubled (IAC IAC) and a record
  # ends with IAC EOR, so this also unescapes IAC IAC and stops at IAC EOR.
  #
  # Returns a hash:
  #   :options  => [[verb, option], ...] from IAC DO/DONT/WILL/WONT
  #   :subneg   => [payload, ...] for each IAC SB ... IAC SE (option byte first,
  #                IAC SE excluded)
  #   :data     => decoded application bytes (IAC IAC collapsed to one 0xFF)
  #   :eor      => true once an IAC EOR record terminator was reached
  #   :consumed => bytes consumed; a trailing incomplete command or
  #                unterminated subnegotiation is left unconsumed for more data
  def parse_telnet_stream(buf)
    options = []
    subneg = []
    data = ''.b
    i = 0
    len = buf.bytesize
    consumed = 0

    while i < len
      b = buf.getbyte(i)
      unless b == IAC
        data << b
        i += 1
        consumed = i
        next
      end

      break if i + 1 >= len # dangling IAC: wait for the next byte

      case buf.getbyte(i + 1)
      when IAC # escaped 0xFF data byte
        data << IAC
        i += 2
      when EOR_CMD # end of record
        return { options: options, subneg: subneg, data: data, eor: true, consumed: i + 2 }
      when SB # subnegotiation: find the terminating IAC SE
        se = nil
        j = i + 2
        while j + 1 < len
          if buf.getbyte(j) == IAC && buf.getbyte(j + 1) == SE
            se = j + 2
            break
          end
          j += 1
        end
        break if se.nil? # subnegotiation not terminated yet: wait for more

        subneg << buf.byteslice(i + 2, (se - 2) - (i + 2))
        i = se
      when DO, DONT, WILL, WONT # 3-byte option command
        break if i + 2 >= len # incomplete: wait for more

        options << [buf.getbyte(i + 1), buf.getbyte(i + 2)]
        i += 3
      else # other 2-byte IAC command
        i += 2
      end

      consumed = i
    end

    { options: options, subneg: subneg, data: data, eor: false, consumed: consumed }
  end

  # Read more bytes into buf until the block is satisfied, raising timeout_msg
  # if the deadline passes or the peer closes first.
  def fill_until(sock, buf, timeout, timeout_msg)
    deadline = Time.now + timeout
    until yield(buf)
      remaining = deadline - Time.now
      raise Tn5250ProtocolError, timeout_msg if remaining <= 0

      chunk = sock.get_once(-1, remaining)
      raise Tn5250ProtocolError, timeout_msg if chunk.nil? || chunk.empty?

      buf << chunk
    end
    buf
  end

  def perform_tn5250_negotiation(sock, term_type, timeout)
    buf = ''.b

    # Phase 1: a 5250 host opens with DO NEW-ENVIRON and DO TERMINAL-TYPE. Wait
    # until both have arrived even if they are split across segments.
    fill_until(sock, buf, timeout, 'did not open with DO NEW-ENVIRON / DO TERMINAL-TYPE, not a 5250 host') do |b|
      opts = parse_telnet_stream(b)[:options]
      opts.include?([DO, OPT_NEWENV]) && opts.include?([DO, OPT_TERMTYPE])
    end
    sock.put([IAC, WILL, OPT_NEWENV, IAC, WILL, OPT_TERMTYPE].pack('C*'))

    # Phase 2: server asks us to SEND our NEW-ENVIRON values (SB NEW-ENVIRON ...
    # IAC SE). Wait for the complete subnegotiation, then read its flags.
    fill_until(sock, buf, timeout, 'timed out waiting for NEW-ENVIRON SEND') do |b|
      parse_telnet_stream(b)[:subneg].any? { |s| s.getbyte(0) == OPT_NEWENV }
    end
    send_subneg = parse_telnet_stream(buf)[:subneg].find { |s| s.getbyte(0) == OPT_NEWENV }
    new_environ_info = parse_new_environ_send(send_subneg)

    sock.put(new_environ_empty_is_reply)
    sock.put(terminal_type_is_reply(term_type))

    # Phase 3 (best effort): the DO EOR / DO BINARY offer usually follows and may
    # be coalesced with the start of the signon record. Wait until the offer
    # arrives or application data begins; a plain (non-E) TN5250 host that skips
    # the offer is still fingerprinted from its panel, so this never hard-fails.
    fill_until(sock, buf, timeout, 'timed out waiting for TN5250E negotiation') do |b|
      parsed = parse_telnet_stream(b)
      parsed[:options].include?([DO, OPT_EOR]) || parsed[:options].include?([DO, OPT_BINARY]) ||
        !parsed[:data].empty? || parsed[:eor]
    end
    parsed = parse_telnet_stream(buf)
    enhanced = parsed[:options].include?([DO, OPT_EOR]) && parsed[:options].include?([DO, OPT_BINARY])

    sock.put([IAC, WILL, OPT_EOR, IAC, DO, OPT_EOR, IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY].pack('C*')) if enhanced

    info = {
      enhanced: enhanced,
      device_type: term_type,
      signon_bypass_offered: new_environ_info[:ibmrseed_offered],
      codepage_offered: new_environ_info[:codepage_offered],
      kbdtype_offered: new_environ_info[:kbdtype_offered]
    }

    # Hand back everything still buffered: it may already hold the start of the
    # WTD record that arrived coalesced with the negotiation replies.
    [info, buf]
  end

  # Returns the decoded application bytes of the signon record. seed carries any
  # bytes already pulled from the socket during negotiation so a record that
  # arrived coalesced with the DO EOR/BINARY offer is not lost. Leftover telnet
  # commands in the stream are skipped, IAC IAC is unescaped, and reading stops
  # at IAC EOR -- the returned bytes contain neither the terminator nor any
  # trailing telnet data.
  def read_wtd_record(sock, timeout, seed = ''.b)
    buf = seed.dup
    deadline = Time.now + timeout

    loop do
      parsed = parse_telnet_stream(buf)
      return parsed[:data] if parsed[:eor]

      remaining = deadline - Time.now
      raise Tn5250ProtocolError, 'timed out waiting for signon record' if remaining <= 0

      chunk = sock.get_once(-1, remaining)
      raise Tn5250ProtocolError, 'connection closed before signon record arrived' if chunk.nil? || chunk.empty?

      buf << chunk
    end
  end

  ORDER_RA = 0x02
  ORDER_SBA = 0x11
  ORDER_IC = 0x13
  ORDER_SF = 0x1d

  # Returns the index of the byte after an SF order and its operands, per
  # RFC 1205: SF [FFW(2, first byte 01xxxxxx)] [FCW(2, first byte 1xxxxxxx)]*
  # attribute(1) length(2). Layout confirmed against a captured IBM i signon
  # panel, where e.g. `1d 40 00 27 00 80` is FFW 4000, attribute 27
  # (non-display), length 0x80 = the "Password (max. 128)" field.
  def consume_sf(bytes, start)
    j = start + 1
    j += 2 if j < bytes.length && (bytes[j] & 0xc0) == 0x40
    j += 2 while j < bytes.length && (bytes[j] & 0x80) != 0
    # attribute byte + 2-byte field length
    [j + 3, bytes.length].min
  end

  def render_wtd(wtd_bytes, rows:, cols:)
    buffer = Array.new(rows) { Array.new(cols, ' ') }
    row = 0
    col = 0
    bytes = wtd_bytes.bytes
    i = 0

    while i < bytes.length
      case bytes[i]
      when ORDER_SBA
        break if i + 2 >= bytes.length

        row = [bytes[i + 1] - 1, 0].max
        col = [bytes[i + 2] - 1, 0].max
        row = rows - 1 if row >= rows
        col = cols - 1 if col >= cols
        i += 3
      when ORDER_RA
        break if i + 3 >= bytes.length

        stop_row = [[bytes[i + 1] - 1, 0].max, rows - 1].min
        stop_col = [[bytes[i + 2] - 1, 0].max, cols - 1].min
        repeat_char = ebcdic_decode(bytes[i + 3])

        loop do
          buffer[row][col] = repeat_char if row < rows && col < cols
          break if row == stop_row && col == stop_col

          col += 1
          if col >= cols
            col = 0
            row += 1
          end
          break if row >= rows
        end
        col += 1
        if col >= cols
          col = 0
          row += 1
        end
        i += 4
      when ORDER_IC
        break if i + 2 >= bytes.length

        i += 3
      when ORDER_SF
        i = consume_sf(bytes, i)
        # the attribute byte occupies one screen cell (rendered blank)
        col += 1
        if col >= cols
          col = 0
          row += 1
        end
      else
        buffer[row][col] = ebcdic_decode(bytes[i]) if row < rows && col < cols
        col += 1
        if col >= cols
          col = 0
          row += 1
        end
        i += 1
      end
    end

    buffer.map(&:join)
  end

  SYSTEM_LABELS = ['Server name', 'System'].freeze
  SUBSYSTEM_LABELS = ['Subsystem'].freeze
  DEVICE_LABELS = ['Display name', 'Display'].freeze

  def looks_like_signon_panel?(screen_rows)
    text = screen_rows.join(' ').downcase
    text.include?('user') && text.include?('password')
  end

  def extract_labeled_value(screen_rows, labels)
    labels.each do |label|
      row = screen_rows.find { |r| r.include?(label) }
      next unless row

      rest = row[(row.index(label) + label.length)..].to_s
      value = rest.sub(/\A[\s.:]+/, '').strip
      return value unless value.empty?
    end
    nil
  end

  def extract_copyright_line(screen_rows)
    row = screen_rows.find { |r| r.include?('COPYRIGHT') }
    row&.strip
  end

  def scrape_signon_panel(screen_rows)
    {
      system: extract_labeled_value(screen_rows, SYSTEM_LABELS),
      subsystem: extract_labeled_value(screen_rows, SUBSYSTEM_LABELS),
      device: extract_labeled_value(screen_rows, DEVICE_LABELS),
      raw_screen: screen_rows.join("\n")
    }
  end

  SCREEN_ROWS = 24
  SCREEN_COLS = 80

  def run_host(ip)
    ::Timeout.timeout(datastore['TIMEOUT'].to_i) do
      connect

      negotiation, record_seed = perform_tn5250_negotiation(sock, datastore['TERM_TYPE'], datastore['TIMEOUT'].to_i)
      record = read_wtd_record(sock, datastore['TIMEOUT'].to_i, record_seed)
      payload = extract_wtd_payload(record)

      if payload.nil?
        print_error('did not send a recognizable Write-To-Display record')
        return
      end

      screen = render_wtd(payload, rows: SCREEN_ROWS, cols: SCREEN_COLS)

      unless looks_like_signon_panel?(screen)
        print_error('does not look like a genuine IBM i TN5250 signon panel')
        vprint_status("raw screen:\n#{screen.join("\n")}")
        return
      end

      fields = scrape_signon_panel(screen)
      report_tn5250_findings(ip, negotiation, fields, screen)
    end
  rescue Tn5250ProtocolError => e
    print_error(e.message)
  rescue ::Rex::ConnectionError, ::Errno::ECONNRESET => e
    vprint_error("connection error: #{e.message}")
  rescue ::Timeout::Error
    vprint_error('timed out')
  ensure
    disconnect
  end

  def report_tn5250_findings(ip, negotiation, fields, screen)
    tls = datastore['SSL'] ? true : false
    copyright = extract_copyright_line(screen)

    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'tn5250',
      info: "IBM i signon; system=#{fields[:system]} subsystem=#{fields[:subsystem]} #{tls ? 'TLS' : 'cleartext'}"
    )

    if fields[:system]
      report_host(
        host: ip,
        os_name: 'IBM i',
        os_flavor: 'OS/400',
        name: fields[:system]
      )
    end

    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      type: 'tn5250.signon',
      data: {
        system: fields[:system],
        subsystem: fields[:subsystem],
        device: fields[:device],
        copyright: copyright,
        tn5250e: negotiation[:enhanced],
        device_type: negotiation[:device_type],
        codepage_offered: negotiation[:codepage_offered],
        kbdtype_offered: negotiation[:kbdtype_offered],
        tls: tls,
        signon_bypass_offered: negotiation[:signon_bypass_offered],
        raw_screen: fields[:raw_screen]
      },
      update: :unique_data
    )

    print_good("System name:  #{fields[:system]}") if fields[:system]
    print_good("Subsystem:    #{fields[:subsystem]}") if fields[:subsystem]
    print_good("Device:       #{fields[:device]}") if fields[:device]
    print_status("TN5250E:     #{negotiation[:enhanced] ? 'supported' : 'no'}")
    print_good('Encrypted/auto-signon offered (IBMRSEED)') if negotiation[:signon_bypass_offered]
    print_warning("Cleartext TN5250 on #{rport}") unless tls
  end
end
