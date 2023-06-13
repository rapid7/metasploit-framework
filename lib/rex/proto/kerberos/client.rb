# -*- coding: binary -*-

require 'rex/stopwatch'

module Rex
  module Proto
    module Kerberos
      # This class is a representation of a kerberos client.
      class Client
        # @!attribute host
        #   @return [String] The kerberos server host
        attr_accessor :host
        # @!attribute port
        #   @return [Integer] The kerberos server port
        attr_accessor :port
        # @!attribute proxies
        #   @return [String,nil] The proxy directive to use for the socket
        attr_accessor :proxies
        # @!attribute timeout
        #   @return [Integer] The connect / read timeout
        attr_accessor :timeout
        # @todo Support UDP
        # @!attribute protocol
        #   @return [String] The transport protocol used (tcp/udp)
        attr_accessor :protocol
        # @!attribute connection
        #   @return [IO] The connection established through Rex sockets
        attr_accessor :connection
        # @!attribute context
        #   @return [Hash] The Msf context where the connection belongs to
        attr_accessor :context

        def initialize(opts = {})
          self.host = opts[:host]
          self.port     = (opts[:port] || 88).to_i
          self.proxies  = opts[:proxies]
          self.timeout  = (opts[:timeout] || 10).to_i
          self.protocol = opts[:protocol] || 'tcp'
          self.context  = opts[:context] || {}
        end

        # Creates a connection through a Rex socket
        #
        # @return [Rex::Socket::Tcp]
        # @raise [RuntimeError] if the connection can not be created
        def connect
          return connection if connection

          case protocol
          when 'tcp'
            self.connection = create_tcp_connection
          when 'udp'
            raise ::NotImplementedError, 'Kerberos Client: UDP not supported'
          else
            raise ::RuntimeError, 'Kerberos Client: unknown transport protocol'
          end

          connection
        end

        # Closes the connection
        def close
          if connection
            connection.shutdown
            connection.close unless connection.closed?
          end

          self.connection = nil
        end

        # Sends a kerberos request through the connection
        #
        # @param req [Rex::Proto::Kerberos::Model::KdcRequest] the request to send
        # @return [Integer] the number of bytes sent
        # @raise [RuntimeError] if the transport protocol is unknown
        # @raise [NotImplementedError] if the transport protocol isn't supported
        def send_request(req)
          connect

          sent = 0
          case protocol
          when 'tcp'
            sent = send_request_tcp(req)
          when 'udp'
            sent = send_request_udp(req)
          else
            raise ::RuntimeError, 'Kerberos Client: unknown transport protocol'
          end

          sent
        end

        # Receives a kerberos response through the connection
        #
        # @return [<Rex::Proto::Kerberos::Model::KrbError, Rex::Proto::Kerberos::Model::KdcResponse>] the kerberos
        #   response message
        # @raise [RuntimeError] if the connection isn't established, the transport protocol is unknown, not supported
        #   or the response can't be parsed
        # @raise [NotImplementedError] if the transport protocol isn't supported
        def recv_response
          if connection.nil?
            raise ::RuntimeError, 'Kerberos Client: connection not established'
          end

          res = nil
          case protocol
          when 'tcp'
            res = recv_response_tcp
          when 'udp'
            res = recv_response_udp
          else
            raise ::RuntimeError, 'Kerberos Client: unknown transport protocol'
          end

          res
        end

        # Sends a kerberos request, and reads the response through the connection
        #
        # @param req [Rex::Proto::Kerberos::Model::KdcRequest] the request to send
        # @return [<Rex::Proto::Kerberos::Model::KrbError, Rex::Proto::Kerberos::Model::KdcResponse>] The kerberos message
        # @raise [RuntimeError] if the transport protocol is unknown or the response can't be parsed.
        # @raise [NotImplementedError] if the transport protocol isn't supported
        def send_recv(req)
          send_request(req)
          res = recv_response

          res
        end

        private

        # Creates a TCP connection using Rex::Socket::Tcp
        #
        # @return [Rex::Socket::Tcp]
        def create_tcp_connection
          self.connection = Rex::Socket::Tcp.create(
            'PeerHost'   => host,
            'PeerPort'   => port.to_i,
            'Proxies'    => proxies,
            'Context'    => context,
            'Timeout'    => timeout
          )
        end

        # Sends a Kerberos Request over a tcp connection
        #
        # @param req [Rex::Proto::Kerberos::Model::KdcRequest] the request to send
        # @return [Integer] the number of bytes sent
        # @raise [RuntimeError] if the request can't be encoded
        def send_request_tcp(req)
          data = req.encode
          length = [data.length].pack('N')
          connection.put(length + data)
        end

        # UDP isn't supported
        #
        # @raise [NotImplementedError]
        def send_request_udp(req)
          raise ::NotImplementedError, 'Kerberos Client: UDP unsupported'
        end

        # Receives a Kerberos Response over a tcp connection
        #
        # @return [<Rex::Proto::Kerberos::Model::KrbError, Rex::Proto::Kerberos::Model::KdcResponse>] the kerberos message response
        # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if the response can't be processed
        # @raise [EOFError] if expected data can't be read
        def recv_response_tcp
          remaining = timeout
          length_raw, elapsed_time = Rex::Stopwatch.elapsed_time do
            connection.get_once(4, remaining)
          end
          remaining -= elapsed_time
          unless length_raw && length_raw.length == 4
            if remaining <= 0
              raise Rex::TimeoutError, 'Kerberos Client: failed to read response length due to timeout'
            end

            raise ::EOFError, 'Kerberos Client: failed to read response length'
          end
          length = length_raw.unpack('N')[0]

          data = ''
          while data.length < length && remaining > 0
            chunk, elapsed_time = Rex::Stopwatch.elapsed_time do
              connection.get_once(length - data.length, remaining)
            end

            remaining -= elapsed_time
            break if chunk.nil?

            data << chunk
          end

          unless data.length == length
            if remaining <= 0
              raise Rex::TimeoutError, 'Kerberos Client: failed to read response due to timeout'
            end

            raise ::EOFError, 'Kerberos Client: failed to read response'
          end

          decode_kerb_response(data)
        end

        # UDP isn't supported
        #
        # @raise [NotImplementedError]
        def recv_response_udp
          raise ::NotImplementedError, 'Kerberos Client: UDP unsupported'
        end

        private

        # Decodes a Kerberos response
        #
        # @param data [String] the raw response message
        # @return [<Rex::Proto::Kerberos::Model::KrbError, Rex::Proto::Kerberos::Model::KdcResponse, Rex::Proto::Kerberos::Model::KrbError>] the kerberos message response
        # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if the response can't be processed
        def decode_kerb_response(data)
          asn1 = OpenSSL::ASN1.decode(data)
          msg_type = asn1.value[0].value[1].value[0].value

          case msg_type
          when Rex::Proto::Kerberos::Model::KRB_ERROR
            res = Rex::Proto::Kerberos::Model::KrbError.decode(asn1)
          when Rex::Proto::Kerberos::Model::AS_REP, Rex::Proto::Kerberos::Model::TGS_REP
            res = Rex::Proto::Kerberos::Model::KdcResponse.decode(asn1)
          when Rex::Proto::Kerberos::Model::AP_REP
            res = Rex::Proto::Kerberos::Model::ApRep.decode(asn1)
          else
            raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Kerberos Client: Unknown response'
          end

          res
        end
      end
    end
  end
end
