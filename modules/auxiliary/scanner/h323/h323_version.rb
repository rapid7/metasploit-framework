##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'H.323 Version Scanner',
      'Description' => 'Detect H.323 Version.',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(1720),
      ], self.class)
  end

  def run_host(ip)

    remote_display    = nil
    remote_product_id = nil
    remote_version_id = nil
    remote_vendor_id  = nil
    remote_protocol   = nil

    begin

    # Wrap this in a timeout to prevent dead services from
    # hanging this thread.
    Timeout.timeout( call_timeout) do

    connect

    caller_name = "SYSTEM\x00"
    h323_id     = Rex::Text.rand_text_alpha(3)
    vendor_id   = Rex::Text.rand_text_alpha(32)
    caller_host = Rex::Socket.source_address( ip )
    caller_port = rand( 32768 ) + 30000
    callee_host = rhost
    callee_port = rport
    conf_guid   = Rex::Text.rand_text(16)
    call_guid   = Rex::Text.rand_text(16)

    pkt_setup = h323_setup_call(caller_name, h323_id, vendor_id, callee_host, callee_port, caller_host, caller_port, conf_guid, call_guid)

    res = sock.put(pkt_setup) rescue nil
    if not res
      disconnect
      return
    end

    cnt = 0
    while( true )
      info = read_packet
      break if not info

      # The remote side of the call disconnected us
      break if info[:type] == @@H323_STATUS_RELEASE_COMPLETE

      remote_display     = info[40].strip if info[40]
      remote_product_id  = info[:product_id].strip if info[:product_id]
      remote_version_id  = info[:version_id].strip if info[:version_id]
      remote_protocol    = info[:protocol_version].strip  if info[:protocol_version]

      if info[:vendor_id] and [nil, "Unknown"].include?( remote_vendor_id )
        remote_vendor_id   = info[:vendor_id].strip
      end

      # Diagnostics
      # print_status("Host: #{rhost}:#{rport} => #{info.inspect}")

      # The remote side of the call was connected (kill it)
      break if info[:type] == @@H323_STATUS_CONNECT

      # Exit if we already received 5 packets from the server
      break if (cnt +=1) > 5

    end

    # Make sure the call was shut down cleanly
    pkt_release = h323_release_call(caller_name, h323_id, vendor_id, callee_host, callee_port, caller_host, caller_port, conf_guid, call_guid)
    sock.put(pkt_release) rescue nil

    # End timeout block
    end

    rescue ::Timeout::Error
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError, ::IOError, ::Errno::ECONNRESET, ::Errno::ENOPROTOOPT
    rescue ::Exception
      print_error("#{rhost}:#{rport} #{$!.class} #{$!} #{$!.backtrace}")
    ensure
      disconnect
    end

    if remote_vendor_id
      remote_product_id   = remote_product_id.to_s.gsub(/[^\x20-\x7e]/, '')
      remote_version_id   = remote_version_id.to_s.gsub(/[^\x20-\x7e]/, '')

      banner = "Protocol: #{ remote_protocol }  VendorID: #{ remote_vendor_id }  "

      if remote_version_id and remote_version_id.length > 0
        banner << "VersionID: #{ remote_version_id }  "
      end

      if remote_product_id and remote_product_id.length > 0
        banner << "ProductID: #{ remote_product_id }  "
      end

      if remote_display and remote_display.length > 0
        remote_display = remote_display.to_s.gsub(/[^\x20-\x7e]/, '')
        banner << "DisplayName: #{ remote_display }"
      end

      print_status("#{rhost}:#{rport} #{banner}")
      report_service(:host => rhost, :port => rport, :name => "h323", :info => banner)
    end

  end

  def read_packet
    begin
      ::Timeout.timeout( read_timeout ) do
        ver = sock.read(2)
        return if not (ver and ver == "\x03\x00")

        bin = sock.read(2)
        return if not bin

        len = [ bin.unpack("n")[0] - 4, 0 ].max
        return if len == 0

        bin = sock.read(len)
        return if not bin

        f_desc, cref_len = bin.unpack("CC")
        cref_val = bin[2, cref_len]
        f_type = bin[2 + cref_len, 1].unpack("C")[0]

        return { :type => f_type, :call_ref => cref_val }.merge( read_ies(f_type, bin[ 2 + cref_len + 1, bin.length] ) )
      end
    rescue ::Timeout::Error
    end
    nil
  end

  def read_ies(mtype, data)
    r = { }
    i = 0

    while( i < (data.length - 1) )
      ie_type = data[i, 1].unpack("C")[0]
      break if not ie_type

      ie_len  = 0
      ie_data = ""

      case ie_type
        when @@H225_IE_USER_USER
          ie_len  = data[i+1, 2].unpack("n")[0]
          break if not ie_len

          ie_data = data[i+3, ie_len]
          break if not ie_data

          i = i + 3 + ie_len
        else
          ie_len  = data[i+1, 1].unpack("C")[0]
          break if not ie_len

          ie_data = data[i+2, ie_len]
          break if not ie_data

          i = i + 2 + ie_len
      end

      r[ ie_type ] = ie_data

      if ie_type == @@H225_IE_USER_USER
        r.merge!( ( read_user_user(mtype, ie_data) rescue {} ) )
      end
    end
    r
  end


  # This provides a weak method of decoding USER-USER PDUs. These are
  # actually PER-encoded ASN.1, but we take a few shortcuts since PER
  # encoding is such a pain.
  def read_user_user(mtype, data)
    r = {}

    # Identify the embedded version (2/3/4/5/6 commonly found)
    i = data.index("\x00\x08\x91\x4a\x00")
    return r if not i

    # Store the protocol version
    pver = data[i + 5, 1].unpack("C")[0]

    r[:protocol_version] = pver.to_s

    # Bump the index over the version
    i+= 6

    # print_line( Rex::Text.to_hex_dump( data[i, 32] ) )

    # Set a placeholder VendorID so this system will be reported
    r[:vendor_id] = "Unknown"

    # We use the version offset to identify the destination block location
    # This changes slightly based on the type of packet we receive
    case mtype
    when @@H323_STATUS_ALERTING, @@H323_STATUS_PROCEEDING

      if pver == 2 and data[i, 2] == "\x20\x00"
        r[ :vendor_id ] = "0x%.8x" %  ( data[i + 2, 4].unpack("N")[0] rescue 0 )
        return r
      end

      # Find the offset to the VendorID
      if data[i + 1, 1] != "\xc0"
        i+= 7
      end

      # Stop processing if we can't identify a VendorID
      return r if data[i + 1, 1] != "\xc0"

      # Otherwise just add 2 to the offset of the version
      i += 2

    when @@H323_STATUS_CONNECT

      # Bail early in some corner cases
      return r if data[i, 1] == "\x00"

      # Find the offset to the VendorID
      if data[i + 1, 1] != "\xc0"
        i+= 7
      end

      # Stop processing if we can't identify a VendorID
      return r if data[i + 1, 1] != "\xc0"

      i += 2

      return r
    else
      return r
    end

    # Extract the manufacturer ID
    r[ :vendor_id ] = "0x%.8x" %  ( data[i, 4].unpack("N")[0] rescue 0 )
    i+= 4

    # No Product ID / Version ID in versions less than 3 (unless special cased above)
    return r if pver < 3

    # Get the product_id length (-1)
    product_id_length = data[i, 1].unpack("C")[0] + 1
    i+= 1

    # Extract the product ID
    r[ :product_id ] = data[i, product_id_length]
    i+= product_id_length

    # Get the version ID length (-1)
    version_id_length = data[i, 1].unpack("C")[0] + 1
    i+= 1

    # Extract the version ID
    r[ :version_id ] = data[i, version_id_length]

    # Thats it for now

    r
  end

  def read_timeout
    10
  end

  def call_timeout
    30
  end


  @@H225_IE_BEARER_CAP   = 0x04
  @@H225_IE_DISPLAY      = 0x28
  @@H225_IE_USER_USER    = 0x7e  # Yes, really User-user


  @@H323_STATUS_ALERTING          = 0x01
  @@H323_STATUS_PROCEEDING        = 0x02
  @@H323_STATUS_SETUP             = 0x05
  @@H323_STATUS_SETUP_ACK         = 0x0D
  @@H323_STATUS_CONNECT           = 0x07
  @@H323_STATUS_RELEASE_COMPLETE  = 0x5a
  @@H323_STATUS_FACILITY          = 0x62


  def encap_tpkt(ver,data)
    [ ver, 0, data.length + 4 ].pack("CCn") + data
  end

  def encap_q225(desc, cref_value, msg_type, data)
    [ desc, cref_value.length, cref_value, msg_type].pack("CCA*C") + data
  end

  def encap_q225_standard(msg_type, data)
    encap_q225(0x08, [0x733f].pack("n"), msg_type, data)
  end

  def encap_q225_setup(data)
    encap_q225_standard(0x05, data)
  end

  def encap_q225_release(data)
    encap_q225_standard(0x5a, data)
  end

  def create_ie_byte(ie_type, data)
    [ie_type, data.length].pack("CC") + data
  end

  def create_ie_short(ie_type, data)
    [ie_type, data.length].pack("Cn") + data
  end

  def create_ie_bearer_capability(cap = 0x00038893)
    create_ie_byte( @@H225_IE_BEARER_CAP, [cap].pack("N")[0,3] )
  end

  def create_ie_display(name = "DEBUG\x00")
    create_ie_byte( @@H225_IE_DISPLAY, name )
  end

  def create_ie_user_user(data)
    create_ie_short( @@H225_IE_USER_USER, data )
  end

  #
  # This is ugly. Doing it properly requires a PER capable ASN.1 encoder, which is overkill for this task
  #
  def create_user_info(h323_id, vendor_id, callee_host, callee_port, caller_host, caller_port, conf_guid, call_guid)
    buff = "\x05" # Protocol descriminator: X.208/X.209 coded user information

    buff << "\x20\xa8\x06\x00\x08\x91\x4a\x00\x06\x01\x40\x02"

    # H323-ID
    buff << h323_id.unpack("C*").pack("n*")

    buff << "\x22\xc0\x09\x00\x00\x3d\x02\x00\x00\x00\x21"

    # VENDOR: 32 + 2 null bytes
    buff << [vendor_id].pack("Z32") + "\x00\x00"

    buff << "\x00"

    # Remote IP + Remote Port
    buff << ( ::Rex::Socket.addr_aton( callee_host ) + [ callee_port.to_i ].pack("n") )

    buff << "\x00"

    # Conference GUID
    buff << conf_guid

    buff << "\x00\xc5\x1d\x80\x04\x07\x00"

    # Local IP + Port
    buff << ( ::Rex::Socket.addr_aton( caller_host ) + [ caller_port.to_i ].pack("n") )

    buff << "\x11\x00"

    # Call GUID
    buff << call_guid

    buff <<
      "\x82\x49\x10\x47\x40\x00\x00\x06\x04\x01\x00\x4c\x10\xb5" +
      "\x00\x00\x26\x25\x73\x70\x65\x65\x78\x20\x73\x72\x3d\x31" +
      "\x36\x30\x30\x30\x3b\x6d\x6f\x64\x65\x3d\x36\x3b\x76\x62" +
      "\x72\x3d\x6f\x66\x66\x3b\x63\x6e\x67\x3d\x6f\x66\x66\x80" +
      "\x12\x1c\x40\x01\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc6\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x90\x3c\x00\x00\x64\x0c\x10\xb5\x00\x00\x26\x25" +
      "\x73\x70\x65\x65\x78\x20\x73\x72\x3d\x31\x36\x30\x30\x30" +
      "\x3b\x6d\x6f\x64\x65\x3d\x36\x3b\x76\x62\x72\x3d\x6f\x66" +
      "\x66\x3b\x63\x6e\x67\x3d\x6f\x66\x66\x80\x0b\x0d\x40\x01" +
      "\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x48\x31\x40\x00\x00\x06\x04\x01\x00\x4c\x10\x09" +
      "\x00\x00\x3d\x0f\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20" +
      "\x57\x69\x64\x65\x36\x80\x12\x1c\x40\x01\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc6\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\xa0\x26\x00\x00\x65\x0c\x10\x09\x00\x00\x3d\x0f" +
      "\x53\x70\x65\x65\x78\x20\x62\x73\x34\x20\x57\x69\x64\x65" +
      "\x36\x80\x0b\x0d\x40\x01\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x50\x1d\x40\x00\x00\x06\x04\x01\x00\x4c\x60\x13" +
      "\x80\x11\x1c\x00\x01\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc6\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x13\x00\x00\x66\x0c\x60\x13\x80\x0b\x0d\x00\x01" +
      "\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x00\x1d\x40\x00\x00\x06\x04\x01\x00\x4c\x20\x13" +
      "\x80\x11\x1c\x00\x01\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc6\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x13\x00\x00\x67\x0c\x20\x13\x80\x0b\x0d\x00\x01" +
      "\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc7\x00\x23\x40\x00\x00\x06\x04\x01\x00\x48\x78\x00" +
      "\x4a\xff\x00\x80\x01\x00\x80\x11\x1c\x00\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc8\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x19\x00\x00\x68\x08\x78\x00\x4a\xff\x00\x80\x01" +
      "\x00\x80\x0b\x0d\x00\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x00\x22\x40\x00\x00\x06\x04\x01\x00\x48\x68\x4a" +
      "\xff\x00\x80\x01\x00\x80\x11\x1c\x00\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc8\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x18\x00\x00\x69\x08\x68\x4a\xff\x00\x80\x01\x00" +
      "\x80\x0b\x0d\x00\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x00\x22\x40\x00\x00\x06\x04\x01\x00\x48\x70\x4a" +
      "\xff\x00\x80\x01\x00\x80\x11\x1c\x00\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc8\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x18\x00\x00\x6a\x08\x70\x4a\xff\x00\x80\x01\x00" +
      "\x80\x0b\x0d\x00\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x00\x2c\x40\x00\x00\x06\x04\x01\x00\x48\xee\x00" +
      "\x00\x20\x9f\xff\x20\x50\x40\x01\x00\x80\x17\x1c\x20\x02" +
      "\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc8\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x80\x04\x48\x08\x8d\x44\x22\x00\x00\x6b\x08\xee" +
      "\x00\x00\x20\x9f\xff\x20\x50\x40\x01\x00\x80\x11\x0d\x20" +
      "\x02\x00" +

      Rex::Socket.addr_aton( caller_host ) +

      "\x13\xc9\x40\x00\x04\x48\x08\x8d\x44\x01\x00\x01\x00\x01" +
      "\x00\x01\x00\x80\xfa\x02\x80\xef\x02\x70\x01\x06\x00\x08" +
      "\x81\x75\x00\x0d\x80\x1a\x80\x01\xf4\x00\x01\x00\x00\x01" +
      "\x00\x00\x01\x00\x04\x02\x05\x00\x48\x08\x8d\x44\x06\x60" +
      "\x01\x00\x01\x80\x0b\x80\x00\x00\x20\x20\xb5\x00\x00\x26" +
      "\x25\x73\x70\x65\x65\x78\x20\x73\x72\x3d\x31\x36\x30\x30" +
      "\x30\x3b\x6d\x6f\x64\x65\x3d\x36\x3b\x76\x62\x72\x3d\x6f" +
      "\x66\x66\x3b\x63\x6e\x67\x3d\x6f\x66\x66\x80\x00\x01\x20" +
      "\x20\x09\x00\x00\x3d\x0f\x53\x70\x65\x65\x78\x20\x62\x73" +
      "\x34\x20\x57\x69\x64\x65\x36\x80\x00\x02\x20\xc0\xef\x80" +
      "\x00\x03\x20\x40\xef\x80\x00\x04\x08\xf0\x00\x4a\xff\x00" +
      "\x80\x01\x00\x80\x00\x05\x08\xd0\x4a\xff\x00\x80\x01\x00" +
      "\x80\x00\x06\x08\xe0\x4a\xff\x00\x80\x01\x00\x80\x00\x07" +
      "\x09\xdc\x00\x00\x40\x9f\xff\x20\x50\x40\x01\x00\x80\x00" +
      "\x08\x83\x01\x50\x80\x00\x09\x83\x01\x10\x80\x00\x0a\x83" +
      "\x01\x40\x80\x00\x0b\x8a\x0c\x14\x0a\x30\x2d\x31\x36\x2c" +
      "\x33\x32\x2c\x33\x36\x00\x80\x01\x03\x03\x00\x00\x00\x01" +
      "\x00\x02\x00\x03\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00" +
      "\x00\x08\x02\x00\x09\x00\x0a\x00\x0b\x07\x01\x00\x32\x80" +
      "\x96\x61\x41\x02\x80\x01\x80"

    buff
  end

  def create_user_release_info(call_guid)
    "\x05" +
    "\x25\x80\x06\x00\x08\x91\x4a\x00\x05\x01\x11\x00" +
    call_guid +
    "\x02\x80\x01\x00"
  end

  def h323_release_call(caller_name, h323_id, vendor_id, callee_host, callee_port, caller_host, caller_port, conf_guid, call_guid)
    encap_tpkt(3,
      encap_q225_release(
        create_ie_display(caller_name) +
        create_ie_user_user(
          create_user_release_info(call_guid )
        )
      )
    )
  end

  def h323_setup_call(caller_name, h323_id, vendor_id, callee_host, callee_port, caller_host, caller_port, conf_guid, call_guid)
    encap_tpkt(3,
      encap_q225_setup(
        create_ie_bearer_capability() +
        create_ie_display(caller_name) +
        create_ie_user_user(
          create_user_info( h323_id, vendor_id, callee_host, callee_port, caller_host, caller_port, conf_guid, call_guid )
        )
      )
    )
  end
end
