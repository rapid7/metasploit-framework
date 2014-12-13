# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      class Client

        attr_accessor :hostname
        attr_accessor :port
        attr_accessor :protocol
        attr_accessor :context
        attr_accessor :connection

        def initialize(opts = {})
          self.hostname = opts[:hostname]
          self.port     = opts[:port] || 88
          self.protocol = opts[:protocol] || 'tcp'
          self.context  = opts[:context] || {}
        end

        def connect
          return connection if connection

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

          connection
        end

        def close
          if connection
            connection.shutdown
            connection.close unless connection.closed?
          end

          self.connection = nil
        end

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

        def send_recv(req)
          send_request(req)
          res = recv_response

          res
        end

        private

        # Sends a Kerberos Request over a tcp connection
        #
        # @param req [Rex::Proto::Kerberos::Model::Message::KdcRequest] the request to send
        # @return [Fixnum] the number of bytes sent
        # @raise [RuntimeError] if the request can't be encoded
        def send_request_tcp(req)
          data = req.encode
          connection.put(data)
        end

        def send_request_udp(req)
          raise ::RuntimeError, 'Kerberos Client: UDP unsupported'
        end

        # Receives a Kerberos Response over a tcp connection
        #
        # @return [String] the data read from the connection
        # @raise [EOFError] if the response can't be read
        def recv_response_tcp
          res = connection.get_once(-1)

          res
        end

        def recv_response_udp
          raise ::RuntimeError, 'Kerberos Client: UDP unsupported'
        end
      end
    end
  end
end
