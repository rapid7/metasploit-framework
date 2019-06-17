module Msf::DBManager::Import::Libpcap
  # The libpcap file format is handled by PacketFu for data
  # extraction. TODO: Make this its own mixin, and possibly
  # extend PacketFu to do better stream analysis on the fly.
  def import_libpcap(args={}, &block)
    data = args[:data]
    wspace = args[:workspace] || args[:wspace]
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    # seen_hosts is only used for determining when to yield an address. Once we get
    # some packet analysis going, the values will have all sorts of info. The plan
    # is to run through all the packets as a first pass and report host and service,
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

    data = PacketFu::PcapFile.new(:filename => filename)
    import_libpcap(args.merge(:data => data))
  end

  # Do all the single packet analysis we can while churning through the pcap
  # the first time. Multiple packet inspection will come later, where we can
  # do stream analysis, compare requests and responses, etc.
  def inspect_single_packet(pkt,wspace,args)
    if pkt.is_tcp? or pkt.is_udp?
      inspect_single_packet_http(pkt,wspace,args)
    end
  end

  # Checks for packets that are headed towards port 80, are tcp, contain an HTTP/1.0
  # line, contains an Authorization line, contains a b64-encoded credential, and
  # extracts it. Reports this credential and solidifies the service as HTTP.
  def inspect_single_packet_http(pkt,wspace,args)
    task = args.fetch(:task, nil)
    # First, check the server side (data from port 80).
    if pkt.is_tcp? and pkt.tcp_src == 80 and !pkt.payload.nil? and !pkt.payload.empty?
      if pkt.payload =~ /^HTTP\x2f1\x2e[01]/n
        http_server_match = pkt.payload.match(/\nServer:\s+([^\r\n]+)[\r\n]/n)
        if http_server_match.kind_of?(MatchData) and http_server_match[1]
          report_service(
              :workspace => wspace,
              :host      => pkt.ip_saddr,
              :port      => pkt.tcp_src,
              :proto     => "tcp",
              :name      => "http",
              :info      => http_server_match[1],
              :state     => Msf::ServiceState::Open,
              :task      => task
          )
          # That's all we want to know from this service.
          return :something_significant
        end
      end
    end

    # Next, check the client side (data to port 80)
    if pkt.is_tcp? and pkt.tcp_dst == 80 and !pkt.payload.nil? and !pkt.payload.empty?
      if pkt.payload.match(/[\x00-\x20]HTTP\x2f1\x2e[10]/n)
        auth_match = pkt.payload.match(/\nAuthorization:\s+Basic\s+([A-Za-z0-9=\x2b]+)/n)
        if auth_match.kind_of?(MatchData) and auth_match[1]
          b64_cred = auth_match[1]
        else
          return false
        end
        # If we're this far, we can surmise that at least the client is a web browser,
        # he thinks the server is HTTP and he just made an authentication attempt. At
        # this point, we'll just believe everything the packet says -- validation ought
        # to come later.
        user,pass = b64_cred.unpack("m*").first.split(/:/,2)
        report_service(
            :workspace => wspace,
            :host      => pkt.ip_daddr,
            :port      => pkt.tcp_dst,
            :proto     => "tcp",
            :name      => "http",
            :task      => task
        )

        service_data = {
            address: pkt.ip_daddr,
            port: pkt.tcp_dst,
            service_name: 'http',
            protocol: 'tcp',
            workspace_id: wspace.id
        }
        service_data[:task_id] = task.id if task

        filename = args[:filename]

        credential_data = {
            origin_type: :import,
            private_data: pass,
            private_type: :password,
            username: user,
            filename: filename
        }
        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
            core: credential_core,
            status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)

        create_credential_login(login_data)

        # That's all we want to know from this service.
        return :something_significant
      end
    end
  end
end
