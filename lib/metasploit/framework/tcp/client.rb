module Metasploit
  module Framework
    module Tcp

      module EvasiveTCP
        attr_accessor :_send_size, :_send_delay, :evasive

        def denagle
          begin
            setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          rescue ::Exception
          end
        end

        def write(buf, opts={})

          return super(buf, opts) if not @evasive

          ret = 0
          idx = 0
          len = @_send_size || buf.length

          while(idx < buf.length)

            if(@_send_delay and idx > 0)
              ::IO.select(nil, nil, nil, @_send_delay)
            end

            pkt = buf[idx, len]

            res = super(pkt, opts)
            flush()

            idx += len
            ret += res if res
          end
          ret
        end
      end

      module Client

        #
        # Establishes a TCP connection to the specified RHOST/RPORT
        #
        # @see Rex::Socket::Tcp
        # @see Rex::Socket::Tcp.create
        def connect(global = true, opts={})

          dossl = false
          if(opts.has_key?('SSL'))
            dossl = opts['SSL']
          else
            dossl = ssl
          end

          nsock = Rex::Socket::Tcp.create(
              'PeerHost'   =>  opts['RHOST'] || rhost,
              'PeerPort'   => (opts['RPORT'] || rport).to_i,
              'LocalHost'  =>  opts['CHOST'] || chost || "0.0.0.0",
              'LocalPort'  => (opts['CPORT'] || cport || 0).to_i,
              'SSL'        =>  dossl,
              'SSLVersion' =>  opts['SSLVersion'] || ssl_version,
              'Proxies'    => proxies,
              'Timeout'    => (opts['ConnectTimeout'] || connection_timeout || 10).to_i
              )

          # enable evasions on this socket
          set_tcp_evasions(nsock)

          # Set this socket to the global socket as necessary
          self.sock = nsock if (global)

          return nsock
        end

        # Enable evasions on a given client
        def set_tcp_evasions(socket)

          if( max_send_size.to_i == 0 and send_delay.to_i == 0)
            return
          end

          return if socket.respond_to?('evasive')

          socket.extend(EvasiveTCP)

          if ( max_send_size.to_i > 0)
            socket._send_size = max_send_size
            socket.denagle
            socket.evasive = true
          end

          if ( send_delay.to_i > 0)
            socket._send_delay = send_delay
            socket.evasive = true
          end
        end

        #
        # Closes the TCP connection
        #
        def disconnect(nsock = self.sock)
          begin
            if (nsock)
              nsock.shutdown
              nsock.close
            end
          rescue IOError
          end

          if (nsock == sock)
            self.sock = nil
          end

        end

        ##
        #
        # Wrappers for getters
        #
        ##

        def max_send_size
          raise NotImplementedError
        end

        def send_delay
          raise NotImplementedError
        end

        #
        # Returns the target host
        #
        def rhost
          raise NotImplementedError
        end

        #
        # Returns the remote port
        #
        def rport
          raise NotImplementedError
        end

        #
        # Returns the local host for outgoing connections
        #
        def chost
          raise NotImplementedError
        end

        #
        # Returns the local port for outgoing connections
        #
        def cport
          raise NotImplementedError
        end

        #
        # Returns the boolean indicating SSL
        #
        def ssl
          raise NotImplementedError
        end

        #
        # Returns the string indicating SSLVersion
        #
        def ssl_version
          raise NotImplementedError
        end

        #
        # Returns the proxy configuration
        #
        def proxies
          raise NotImplementedError
        end

        attr_accessor :sock

      end
    end
  end
end
