# -*- coding: binary -*-

module Rex
  module Proto
    module DHCPv6
      # A DHCPv6 client/server message (RFC 8415 section 8): a one-byte message
      # type, a three-byte transaction id, and a list of TLV options. This parses
      # and builds the wire format and provides helpers for assembling the rogue
      # server responses used to make a client adopt the attacker as its DNS server.
      #
      # Relay messages (RELAY-FORW / RELAY-REPL) have a different layout and are not
      # modelled here; only direct client/server messages are handled.
      class Packet < BinData::Record
        # A single DHCPv6 option in TLV form (RFC 8415 section 21.1). Nested so it
        # registers with BinData under the unique name :dhcpv6_option (a bare
        # :option would collide with other protocols' option records).
        class Dhcpv6Option < BinData::Record
          endian :big

          uint16 :code
          uint16 :len, value: -> { data.num_bytes }
          string :data, read_length: :len
        end

        endian :big

        uint8  :msg_type
        string :transaction_id, length: 3
        array  :options, type: :dhcpv6_option, read_until: :eof

        # @return [Rex::Proto::DHCPv6::Packet::Dhcpv6Option, nil] the first option
        #   with the given code, if present.
        def find_option(code)
          options.find { |opt| opt.code == code }
        end

        # @return [Boolean] whether the client asked for a Rapid Commit (a two-message
        #   Solicit/Reply exchange rather than the four-message default).
        def rapid_commit?
          !find_option(Constants::OptionCode::RAPID_COMMIT).nil?
        end

        class << self
          # Build a DHCPv6 option.
          #
          # @param code [Integer] the option code
          # @param data [String] the option payload (already encoded)
          # @return [Rex::Proto::DHCPv6::Packet::Dhcpv6Option]
          def option(code, data)
            Dhcpv6Option.new(code: code, data: data.b)
          end

          # Build a DUID-LL (link-layer address DUID, RFC 8415 section 11.4).
          #
          # @param mac [String] the link-layer address, as "aa:bb:cc:dd:ee:ff" or 6 raw bytes
          # @return [String] the encoded DUID
          def duid_ll(mac)
            [Constants::DuidType::LL, Constants::HARDWARE_TYPE_ETHERNET].pack('nn') + mac_to_bytes(mac)
          end

          # Build a DNS Recursive Name Server option (RFC 3646): the list of IPv6
          # addresses the client should use as DNS servers.
          #
          # @param addresses [Array<String>] IPv6 addresses in presentation form
          # @return [Rex::Proto::DHCPv6::Packet::Dhcpv6Option]
          def dns_servers_option(addresses)
            option(Constants::OptionCode::DNS_SERVERS, addresses.map { |a| Rex::Socket.addr_aton(a) }.join)
          end

          # Build a Domain Search List option (RFC 3646), DNS-name encoded.
          #
          # @param domains [Array<String>] search domains
          # @return [Rex::Proto::DHCPv6::Packet::Dhcpv6Option]
          def domain_list_option(domains)
            option(Constants::OptionCode::DOMAIN_LIST, domains.map { |d| encode_dns_name(d) }.join)
          end

          # Build an IA_NA (Identity Association for Non-temporary Addresses) option
          # carrying a single leased address, echoing the client's IAID.
          #
          # @param iaid [Integer] the client's IAID (from its IA_NA request)
          # @param address [String] the IPv6 address to lease, in presentation form
          # @param preferred_lifetime [Integer] seconds
          # @param valid_lifetime [Integer] seconds
          # @param t1 [Integer] renew timer, seconds
          # @param t2 [Integer] rebind timer, seconds
          # @return [Rex::Proto::DHCPv6::Packet::Dhcpv6Option]
          def ia_na_option(iaid:, address:, preferred_lifetime:, valid_lifetime:, t1:, t2:)
            iaaddr = option(
              Constants::OptionCode::IAADDR,
              Rex::Socket.addr_aton(address) + [preferred_lifetime, valid_lifetime].pack('NN')
            )
            option(Constants::OptionCode::IA_NA, [iaid, t1, t2].pack('NNN') + iaaddr.to_binary_s)
          end

          # Read the IAID out of a request's IA_NA option, if any.
          #
          # @param request [Rex::Proto::DHCPv6::Packet]
          # @return [Integer, nil]
          def request_iaid(request)
            ia_na = request.find_option(Constants::OptionCode::IA_NA)
            return nil if ia_na.nil?

            ia_na.data.to_binary_s[0, 4].unpack1('N')
          end

          # The message type to answer a given request with (RFC 8415 section 18.3):
          # a Solicit is answered with an Advertise, unless Rapid Commit is requested,
          # in which case the exchange collapses to a Reply. Everything else we handle
          # (Request/Renew/Rebind/Confirm/Information-Request) is answered with a Reply.
          #
          # @param request [Rex::Proto::DHCPv6::Packet]
          # @return [Integer, nil] the response message type, or nil if we do not answer it
          def response_type_for(request)
            case request.msg_type
            when Constants::MessageType::SOLICIT
              request.rapid_commit? ? Constants::MessageType::REPLY : Constants::MessageType::ADVERTISE
            when Constants::MessageType::REQUEST,
                 Constants::MessageType::RENEW,
                 Constants::MessageType::REBIND,
                 Constants::MessageType::CONFIRM,
                 Constants::MessageType::INFORMATION_REQUEST
              Constants::MessageType::REPLY
            end
          end

          # Assemble a rogue server response that advertises the attacker as the
          # client's DNS server. Echoes the client's transaction id and Client ID,
          # and (for stateful requests carrying an IA_NA) leases the given address.
          #
          # @param request [Rex::Proto::DHCPv6::Packet] the parsed client message
          # @param server_duid [String] the encoded server DUID (see {.duid_ll})
          # @param dns_servers [Array<String>] DNS server IPv6 addresses to hand out
          # @param assigned_address [String, nil] address to lease, if answering statefully
          # @param preferred_lifetime [Integer] lease preferred lifetime, seconds
          # @param valid_lifetime [Integer] lease valid lifetime, seconds
          # @param domain_list [Array<String>, nil] optional DNS search domains
          # @return [Rex::Proto::DHCPv6::Packet, nil] the response, or nil if the
          #   request type is not one we answer
          def build_response(request:, server_duid:, dns_servers:, assigned_address: nil,
                             preferred_lifetime: 300, valid_lifetime: 600, domain_list: nil)
            response_type = response_type_for(request)
            return nil if response_type.nil?

            opts = [
              option(Constants::OptionCode::SERVERID, server_duid)
            ]

            client_id = request.find_option(Constants::OptionCode::CLIENTID)
            opts << option(Constants::OptionCode::CLIENTID, client_id.data.to_binary_s) unless client_id.nil?

            iaid = request_iaid(request)
            if !iaid.nil? && !assigned_address.nil?
              opts << ia_na_option(
                iaid: iaid,
                address: assigned_address,
                preferred_lifetime: preferred_lifetime,
                valid_lifetime: valid_lifetime,
                t1: preferred_lifetime / 2,
                t2: (preferred_lifetime * 4) / 5
              )
            end

            opts << dns_servers_option(dns_servers)
            opts << domain_list_option(domain_list) unless domain_list.nil? || domain_list.empty?
            opts << option(Constants::OptionCode::RAPID_COMMIT, '') if request.rapid_commit?

            new(
              msg_type: response_type,
              transaction_id: request.transaction_id.to_binary_s,
              options: opts.map { |o| { code: o.code, data: o.data.to_binary_s } }
            )
          end

          private

          def mac_to_bytes(mac)
            return mac.b if mac.b.bytesize == 6

            [mac.delete(':-')].pack('H*')
          end

          # Encode a domain name as a sequence of length-prefixed labels terminated
          # by a zero-length root label (RFC 1035 section 3.1).
          def encode_dns_name(domain)
            domain.split('.').map { |label| [label.bytesize].pack('C') + label }.join + "\x00"
          end
        end
      end
    end
  end
end
