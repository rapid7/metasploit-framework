module Msf::DBManager::Import::Libpcap
  # The libpcap file format is handled by PacketFu for data
  # extraction. TODO: Make this its own mixin, and possibly
  # extend PacketFu to do better stream analysis on the fly.
  def import_libpcap(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    # seen_hosts is only used for determining when to yield an address. Once we get
    # some packet analysis going, the values will have all sorts of info. The plan
    # is to ru through all the packets as a first pass and report host and service,
    # then, once we have everything parsed, we can reconstruct sessions and ngrep
    # out things like authentication sequences, examine ttl's and window sizes, all
    # kinds of crazy awesome stuff like that.
    seen_hosts = {}
    decoded_packets = 0
    last_count = 0
    data.read_packet_bytes do |p|
      if (decoded_packets >= last_count + 1000) and block
        yield(:pcap_count, decoded_packets)
        last_count = decoded_packets
      end
      decoded_packets += 1

      pkt = PacketFu::Packet.parse(p) rescue next # Just silently skip bad packets

      next unless pkt.is_ip? # Skip anything that's not IP. Technically, not Ethernet::Ip
      next if pkt.is_tcp? && (pkt.tcp_src == 0 || pkt.tcp_dst == 0) # Skip port 0
      next if pkt.is_udp? && (pkt.udp_src == 0 || pkt.udp_dst == 0) # Skip port 0
      saddr = pkt.ip_saddr
      daddr = pkt.ip_daddr

      # Handle blacklists and obviously useless IP addresses, and report the host.
      next if (bl | [saddr,daddr]).size == bl.size # Both hosts are blacklisted, skip everything.
      unless( bl.include?(saddr) || rfc3330_reserved(saddr))
        yield(:address,saddr) if block and !seen_hosts.keys.include?(saddr)
        unless seen_hosts[saddr]
          report_host(
              :workspace => wspace,
              :host      => saddr,
              :state     => Msf::HostState::Alive,
              :task      => args[:task]
          )
        end
        seen_hosts[saddr] ||= []

      end
      unless( bl.include?(daddr) || rfc3330_reserved(daddr))
        yield(:address,daddr) if block and !seen_hosts.keys.include?(daddr)
        unless seen_hosts[daddr]
          report_host(
              :workspace => wspace,
              :host      => daddr,
              :state     => Msf::HostState::Alive,
              :task      => args[:task]
          )
        end
        seen_hosts[daddr] ||= []
      end

      if pkt.is_tcp? # First pass on TCP packets
        if (pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 1) or # Oh, this kills me
          pkt.tcp_src < 1024 # If it's a low port, assume it's a proper service.
          if seen_hosts[saddr]
            unless seen_hosts[saddr].include? [pkt.tcp_src,"tcp"]
              report_service(
                  :workspace => wspace, :host => saddr,
                  :proto     => "tcp", :port => pkt.tcp_src,
                  :state     => Msf::ServiceState::Open,
                  :task      => args[:task]
              )
              seen_hosts[saddr] << [pkt.tcp_src,"tcp"]
              yield(:service,"%s:%d/%s" % [saddr,pkt.tcp_src,"tcp"])
            end
          end
        end
      elsif pkt.is_udp? # First pass on UDP packets
        if pkt.udp_src == pkt.udp_dst # Very basic p2p detection.
          [saddr,daddr].each do |xaddr|
            if seen_hosts[xaddr]
              unless seen_hosts[xaddr].include? [pkt.udp_src,"udp"]
                report_service(
                    :workspace => wspace, :host => xaddr,
                    :proto     => "udp", :port => pkt.udp_src,
                    :state     => Msf::ServiceState::Open,
                    :task      => args[:task]
                )
                seen_hosts[xaddr] << [pkt.udp_src,"udp"]
                yield(:service,"%s:%d/%s" % [xaddr,pkt.udp_src,"udp"])
              end
            end
          end
        elsif pkt.udp_src < 1024 # Probably a service
          if seen_hosts[saddr]
            unless seen_hosts[saddr].include? [pkt.udp_src,"udp"]
              report_service(
                  :workspace => wspace, :host => saddr,
                  :proto     => "udp", :port => pkt.udp_src,
                  :state     => Msf::ServiceState::Open,
                  :task      => args[:task]
              )
              seen_hosts[saddr] << [pkt.udp_src,"udp"]
              yield(:service,"%s:%d/%s" % [saddr,pkt.udp_src,"udp"])
            end
          end
        end
      end # tcp or udp

      inspect_single_packet(pkt,wspace,args)

    end # data.body.map

    # Right about here, we should have built up some streams for some stream analysis.
    # Not sure what form that will take, but people like shoving many hundreds of
    # thousands of packets through this thing, so it'll need to be memory efficient.

  end

  def import_libpcap_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = PacketFu::PcapFile.new(:filename => filename)
    import_libpcap(args.merge(:data => data))
  end
end
