# -*- coding: binary -*-

require 'rex/socket'
require 'net/ldap'

module Rex
  module Proto
    module LDAP
      class Server
        attr_reader :serve_udp, :serve_tcp, :sock_options, :udp_sock, :tcp_sock, :syntax, :ldif

        module LdapClient
          attr_accessor :authenticated

          #
          # Initialize LDAP client state
          #
          def init_ldap_client
            self.authenticated = false
          end
        end

        class MockLdapClient
          attr_reader :peerhost, :peerport, :srvsock

          #
          # Create mock LDAP client
          #
          # @param host [String] PeerHost IP address
          # @param port [Fixnum] PeerPort integer
          # @param sock [Socket] Connection socket
          def initialize(host, port, sock)
            @peerhost = host
            @peerport = port
            @srvsock = sock
          end

          #
          # Test method to prevent GC/ObjectSpace abuse via class lookups
          #
          def mock_ldap_client?
            true
          end

          def write(data)
            srvsock.sendto(data, peerhost, peerport)
          end
        end

        include Rex::IO::GramServer
        #
        # Create LDAP Server
        #
        # @param lhost [String] Listener address
        # @param lport [Fixnum] Listener port
        # @param udp [TrueClass, FalseClass] Listen on UDP socket
        # @param tcp [TrueClass, FalseClass] Listen on TCP socket
        # @param ldif [String] LDIF data
        # @param auth_provider [Rex::Proto::LDAP::Auth] LDAP Authentication provider which processes authentication
        # @param ctx [Hash] Framework context for sockets
        # @param dblock [Proc] Handler for :dispatch_request flow control interception
        # @param sblock [Proc] Handler for :send_response flow control interception
        #
        # @return [Rex::Proto::LDAP::Server] LDAP Server object
        def initialize(lhost = '0.0.0.0', lport = 389, udp = true, tcp = true, ldif = nil, comm = nil, auth_provider = nil, ctx = {}, dblock = nil, sblock = nil)
          @serve_udp = udp
          @serve_tcp = tcp
          @sock_options = {
            'LocalHost' => lhost,
            'LocalPort' => lport,
            'Context' => ctx,
            'Comm' => comm
          }
          @ldif = ldif
          self.listener_thread = nil
          self.dispatch_request_proc = dblock
          self.send_response_proc = sblock
          @auth_provider  = auth_provider
        end

        #
        # Check if server is running
        #
        def running?
          listener_thread and listener_thread.alive?
        end

        #
        # Start the LDAP server
        #
        def start
          if serve_udp
            @udp_sock = Rex::Socket::Udp.create(sock_options)
            self.listener_thread = Rex::ThreadFactory.spawn('UDPLDAPServerListener', false) do
              monitor_listener
            end
          end

          if serve_tcp
            @tcp_sock = Rex::Socket::TcpServer.create(sock_options)
            tcp_sock.on_client_connect_proc = proc do |cli|
              on_client_connect(cli)
            end
            tcp_sock.on_client_data_proc = proc do |cli|
              on_client_data(cli)
            end
            # Close UDP socket if TCP socket fails
            begin
              tcp_sock.start
            rescue StandardError => e
              stop
              raise e
            end
            unless serve_udp
              self.listener_thread = tcp_sock.listener_thread
            end
          end

          @auth_provider ||= Rex::Proto::LDAP::Auth.new(nil, nil, nil, nil, nil)

          self
        end

        #
        # Stop the LDAP server
        #
        def stop
          ensure_close = [udp_sock, tcp_sock].compact
          begin
            listener_thread.kill if listener_thread.respond_to?(:kill)
            self.listener_thread = nil
          ensure
            while csock = ensure_close.shift
              csock.stop if csock.respond_to?(:stop)
              csock.close unless csock.respond_to?(:close) && csock.closed?
            end
          end
        end

        #
        # Process client request, handled with dispatch_request_proc if set
        #
        # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
        # @param data [String] raw LDAP request data
        def dispatch_request(cli, data)
          if dispatch_request_proc
            dispatch_request_proc.call(cli, data)
          else
            default_dispatch_request(cli, data)
          end
        end

        #
        # Default LDAP request dispatcher
        #
        # @param client [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
        # @param data [String] raw LDAP request data
        def default_dispatch_request(client, data)
          return if data.strip.empty? || data.strip.nil?

          processed_pdu_data = {
            ip: client.peerhost,
            port: client.peerport,
            service_name: 'ldap',
            post_pdu: false
          }

          data.extend(Net::BER::Extensions::String)
          begin
            pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
            wlog("LDAP request data remaining: #{data}") unless data.empty?

            res = case pdu.app_tag
                  when Net::LDAP::PDU::BindRequest
                    user_login = pdu.bind_parameters
                    server_creds = ''
                    context_code = nil
                    processed_pdu_data = @auth_provider.process_login_request(user_login).merge(processed_pdu_data)
                    if processed_pdu_data[:result_code] == Net::LDAP::ResultCodeSaslBindInProgress
                      server_creds = processed_pdu_data[:server_creds]
                      context_code = 7
                    else
                      processed_pdu_data[:result_message] = "LDAP Login Attempt => From:#{processed_pdu_data[:ip]}:#{processed_pdu_data[:port]}\t Username:#{processed_pdu_data[:user]}\t #{processed_pdu_data[:private_type]}:#{processed_pdu_data[:private]}\t"
                      processed_pdu_data[:result_message] += " Domain:#{processed_pdu_data[:domain]}" if processed_pdu_data[:domain]
                      processed_pdu_data[:post_pdu] = true
                    end
                    processed_pdu_data[:pdu_type] = pdu.app_tag
                    encode_ldap_response(
                      pdu.message_id,
                      processed_pdu_data[:result_code],
                      '',
                      Net::LDAP::ResultStrings[processed_pdu_data[:result_code]],
                      Net::LDAP::PDU::BindResult,
                      server_creds,
                      context_code
                    )
                  when Net::LDAP::PDU::SearchRequest
                    filter = Net::LDAP::Filter.parse_ldap_filter(pdu.search_parameters[:filter])
                    attrs = pdu.search_parameters[:attributes].empty? ? :all : pdu.search_parameters[:attributes]
                    res = search_result(filter, pdu.message_id, attrs)
                    if res.nil? || res.empty?
                      result_code = Net::LDAP::ResultCodeNoSuchObject
                    else
                      client.write(res)
                      result_code = Net::LDAP::ResultCodeSuccess
                    end
                    processed_pdu_data[:pdu_type] = pdu.app_tag
                    encode_ldap_response(
                      pdu.message_id,
                      result_code,
                      '',
                      Net::LDAP::ResultStrings[result_code],
                      Net::LDAP::PDU::SearchResult
                    )
                  when Net::LDAP::PDU::UnbindRequest
                    client.close
                    nil
                  else
                    if suitable_response(pdu.app_tag)
                      result_code = Net::LDAP::ResultCodeUnwillingToPerform
                      encode_ldap_response(
                        pdu.message_id,
                        result_code,
                        '',
                        Net::LDAP::ResultStrings[result_code],
                        suitable_response(pdu.app_tag)
                      )
                    else
                      client.close
                    end
                  end

            if @pdu_process[pdu.app_tag] && !processed_pdu_data.empty?
              @pdu_process[pdu.app_tag].call(processed_pdu_data)
            end
            send_response(client, res) unless res.nil?
          rescue StandardError => e
            elog(e)
            client.close
            raise e
          end
        end

        #
        # Encode response for LDAP client consumption
        #
        # @param msgid        [Integer] LDAP message identifier
        # @param code         [Integer] LDAP message code
        # @param dn           [String]  LDAP distinguished name
        # @param msg          [String]  LDAP response message
        # @param tag          [Integer] LDAP response tag
        # @param context_data [String]  Additional data to serialize in the sequence
        # @param context_code [Integer] Context Specific code related to `context_data`
        #
        # @return [Net::BER::BerIdentifiedOid] LDAP query response
        def encode_ldap_response(msgid, code, dn, msg, tag, context_data = nil, context_code = nil)
          tag_sequence = [
            code.to_ber_enumerated,
            dn.to_ber,
            msg.to_ber
          ]

          if context_data && context_code
            tag_sequence << context_data.to_ber_contextspecific(context_code)
          end

          [
            msgid.to_ber,
            tag_sequence.to_ber_appsequence(tag)
          ].to_ber_sequence
        end

        #
        # Search provided ldif data for query information. If no `ldif` was provided a random search result will be generated.
        #
        # @param filter [Net::LDAP::Filter] LDAP query filter
        # @param attrflt [Array, Symbol] LDAP attribute filter
        #
        # @return [Array] Query matches

        def search_result(filter, msgid, attrflt = :all)
          if @ldif.nil? || @ldif.empty?
            attrs = []
            if attrflt.is_a?(Array)
              attrflt.each do |at|
                attrval = [Rex::Text.rand_text_alphanumeric(10)].map(&:to_ber).to_ber_set
                attrs << [at.to_ber, attrval].to_ber_sequence
              end
              dn = "dc=#{Rex::Text.rand_text_alphanumeric(10)},dc=#{Rex::Text.rand_text_alpha(4)}"
              appseq = [
                dn.to_ber,
                attrs.to_ber_sequence
              ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
              [msgid.to_ber, appseq].to_ber_sequence
            end
          else
            ldif.map do |bind_dn, entry|
              next unless filter.match(entry)

              attrs = []
              entry.each do |k, v|
                if attrflt == :all || attrflt.include?(k.downcase)
                  attrvals = v.map(&:to_ber).to_ber_set
                  attrs << [k.to_ber, attrvals].to_ber_sequence
                end
              end
              appseq = [
                bind_dn.to_ber,
                attrs.to_ber_sequence
              ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
              [msgid.to_ber, appseq].to_ber_sequence
            end.compact.join
          end
        end

        #
        # Sets the tasks to be performed after processing of pdu object
        #
        # @param proc [Proc] block of code to execute
        #
        # @return pdu_process [Proc] steps to be executed
        def processed_pdu_handler(pdu_type, &proc)
          @pdu_process = []
          @pdu_process[pdu_type] = proc if block_given?
        end

        #
        # Returns the hardcore alias for the LDAP service
        #
        def self.hardcore_alias(*args)
          "#{args[0] || ''}-#{args[1] || ''}-#{args[4] || ''}"
        end

        #
        # Get suitable response for a particular request
        #
        # @param request [Integer] Type of request
        #
        # @return response [Integer] Type of response
        def suitable_response(request)
          responses = {
            Net::LDAP::PDU::BindRequest => Net::LDAP::PDU::BindResult,
            Net::LDAP::PDU::SearchRequest => Net::LDAP::PDU::SearchResult,
            Net::LDAP::PDU::ModifyRequest => Net::LDAP::PDU::ModifyResponse,
            Net::LDAP::PDU::AddRequest => Net::LDAP::PDU::AddResponse,
            Net::LDAP::PDU::DeleteRequest => Net::LDAP::PDU::DeleteResponse,
            Net::LDAP::PDU::ModifyRDNRequest => Net::LDAP::PDU::ModifyRDNResponse,
            Net::LDAP::PDU::CompareRequest => Net::LDAP::PDU::CompareResponse,
            Net::LDAP::PDU::ExtendedRequest => Net::LDAP::PDU::ExtendedResponse
          }

          responses[request]
        end

        #
        # LDAP server.
        #
        def alias
          'LDAP Server'
        end

        protected

        #
        # This method monitors the listener socket for new connections and calls
        # the +on_client_connect+ callback routine.
        #
        def monitor_listener
          loop do
            rds = [udp_sock]
            wds = []
            eds = [udp_sock]

            r, = ::IO.select(rds, wds, eds, 1)

            next unless (!r.nil? && (r[0] == udp_sock))

            buf, host, port = udp_sock.recvfrom(65535)
            # Mock up a client object for sending back data
            cli = MockLdapClient.new(host, port, r[0])
            cli.extend(LdapClient)
            cli.init_ldap_client
            dispatch_request(cli, buf)
          end
        end

        #
        # Processes request coming from client
        #
        # @param cli [Rex::Socket::Tcp] Client sending request
        def on_client_data(cli)
          data = cli.read(65535)
          raise ::EOFError if !data
          raise ::EOFError if data.empty?

          dispatch_request(cli, data)
        rescue EOFError => e
          tcp_sock.close_client(cli) if cli
          raise e
        end

        #
        # Extend client for LDAP state
        #
        def on_client_connect(cli)
          cli.extend(LdapClient)
          cli.init_ldap_client
        end

      end
    end
  end
end
