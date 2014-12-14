# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      # This class is a representation of kerberos client.
      class Client
        # @!attribute hostname
        #   @return [String] The kerberos server hostname
        attr_accessor :hostname
        # @!attribute port
        #   @return [Fixnum] The kerberos server port
        attr_accessor :port
        # @!attribute protocol
        #   @return [String] The transport protocol used (tcp/udp)
        attr_accessor :protocol
        # @!attribute context
        #   @return [Hash]
        attr_accessor :context
        # @!attribute connection
        #   @return [IO]
        attr_accessor :connection

        def initialize(opts = {})
          self.hostname = opts[:hostname]
          self.port     = opts[:port] || 88
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
            raise ::RuntimeError, 'Kerberos Client: UDP unsupported'
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
        # @param req [Rex::Proto::Kerberos::Model::Message::KdcRequest] the request to send
        # @return [Fixnum] the number of bytes sent
        # @raise [RuntimeError] if the transport protocol is unknown or not supported
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
        # @return [String] the kerberos response raw message
        # @raise [RuntimeError] if the connection isn't established
        # @raise [RuntimeError] if the transport protocol is unknown or unsupported
        # @raise [RuntimeError] if the response can't be parsed
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
        # @param req [Rex::Proto::Kerberos::Model::Message::KdcRequest] the request to sent
        # @return [String] The raw kerberos response message
        # @raise [RuntimeError] if the transport protocol is unknown or unsupported
        # @raise [RuntimeError] if the response can't be parsed
        def send_recv(req)
          send_request(req)
          res = recv_response

          res
        end

        private

        # Creates a TCP connection
        #
        # @return [Rex::Socket::Tcp]
        def create_tcp_connection
          #timeout = (t.nil? or t == -1) ? 0 : t
          timeout = 0
          
          self.connection = Rex::Socket::Tcp.create(
            'PeerHost'   => hostname,
            'PeerPort'   => port.to_i,
            #'LocalHost'  => self.local_host,
            #'LocalPort'  => self.local_port,
            'Context'    => context,
            #'Proxies'    => self.proxies,
            'Timeout'    => timeout
          )
        end

        # Sends a Kerberos Request over a tcp connection
        #
        # @param req [Rex::Proto::Kerberos::Model::Message::KdcRequest] the request to send
        # @return [Fixnum] the number of bytes sent
        # @raise [RuntimeError] if the request can't be encoded
        def send_request_tcp(req)
          data = req.encode
          length = [data.length].pack('N')
          connection.put(length + data)
        end

        def send_request_udp(req)
          raise ::RuntimeError, 'Kerberos Client: UDP unsupported'
        end

        # Receives a Kerberos Response over a tcp connection
        #
        # @return [String] the raw kerberos message
        # @raise [RuntimeError] if the response can't be read
        # @raise [EOFError] if expected data can't be read
        def recv_response_tcp
          length_raw = connection.get_once(4)
          unless length_raw && length_raw.length == 4
            raise ::RuntimeError, 'Kerberos Client: failed to read response'
          end
          length = length_raw.unpack('N')[0]

          data = connection.get_once(length)
          unless data && data.length == length
            raise ::RuntimeError, 'Kerberos Client: failed to read response'
          end

          data
        end

        def recv_response_udp
          raise ::RuntimeError, 'Kerberos Client: UDP unsupported'
        end
      end
    end
  end
end
