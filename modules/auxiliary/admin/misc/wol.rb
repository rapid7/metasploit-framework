##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'UDP Wake-On-Lan (WOL)',
      'Description'    => %q{
          This module will turn on a remote machine with a network card that
        supports wake-on-lan (or MagicPacket).  In order to use this, you must
        know the machine's MAC address in advance.  The current default MAC
        address is just an example of how your input should look like.

          The password field is optional.  If present, it should be in this hex
        format: 001122334455, which is translated to "0x001122334455" in binary.
        Note that this should be either 4 or 6 bytes long.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ]
    ))

    deregister_udp_options

    register_options(
      [
        OptString.new("MAC",      [true, 'Specify a MAC address', '00:90:27:85:cf:01']),
        OptString.new("PASSWORD", [false, 'Specify a four or six-byte password']),
        OptBool.new("IPV6",       [false, 'Use IPv6 broadcast', false])
      ])
  end

  #
  # Convert the MAC option to binary format
  #
  def get_mac_addr
    mac = datastore['MAC']
    if mac !~ /^([0-9a-zA-Z]{2}\:){5}[0-9a-zA-Z]{2}$/
      print_error("Invalid MAC address format")
      return nil
    end

    bin_mac = ''
    mac.split(':').each do |group|
      bin_mac << [group].pack('H*')
    end

    bin_mac
  end

  #
  # Supply a password to go with the WOL packet (SecureON)
  #
  def parse_password
    return "" if datastore['PASSWORD'].nil?

    dataset = [ datastore['PASSWORD'] ].pack('H*').unpack('C*')

    # According to Wireshark wiki, this must be either 4 or 6 bytes
    if dataset.length == 4 or dataset.length == 6
      pass = ''
      dataset.each do |group|
        pass << group.to_i
      end

      return pass
    else
      print_error("Bad password format or length: #{dataset.inspect}")
    end

    nil
  end

  def wol_rhost
    datastore['IPV6'] ? "ff:ff:ff:ff:ff:ff" : "255.255.255.255"
  end

  def wol_rport
    9
  end

  def run
    # If the MAC is bad, no point to continue
    mac = get_mac_addr
    return if mac.nil?

    # If there's a password, use it
    pass = parse_password
    return if pass.nil?

    # Craft the WOL packet
    wol_pkt = "\xff" * 6  #Sync stream (magic packet)
    wol_pkt << mac  * 16  #Mac address
    wol_pkt << pass if not pass.empty?

    # Send out the packet
    print_status("Sending WOL packet...")
    connect_udp( true, {
      'RHOST' => wol_rhost,
      'RPORT' => wol_rport
    })
    udp_sock.put(wol_pkt)
    disconnect_udp
  end
end

=begin
http://wiki.wireshark.org/WakeOnLAN

Test:
udp && eth.addr == ff:ff:ff:ff:ff:ff
=end
