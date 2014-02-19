##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Simple IP Spoofing Tester',
      'Version'     => '$Revision$',
      'Description' => 'Simple IP Spoofing Tester',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    begin
      require 'pcaprub'
      @@havepcap = true
    rescue ::LoadError
      @@havepcap = false
    end

    deregister_options('FILTER','PCAPFILE')

  end

  def run_host(ip)
    open_pcap
    p = PacketFu::UDPPacket.new
    p.ip_saddr = ip
    p.ip_daddr = ip
    p.ip_ttl = 255
    p.udp_sport = 53
    p.udp_dport = 53
    p.payload  = "HELLO WORLD"
    p.recalc
    ret = send(ip,p)
    if ret == :done
      print_good("#{ip}: Sent a packet to #{ip} from #{ip}")
    else
      print_error("#{ip}: Packet not sent. Check permissions & interface.")
    end
    close_pcap
  end

  def send(ip,pkt)
    begin
      capture_sendto(pkt, ip)
    rescue RuntimeError => e
      return :error
    end
    return :done
  end


end
