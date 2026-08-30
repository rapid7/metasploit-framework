module Msf
  module Handler
    # Options and methods needed for all handlers that listen for a connection
    # from the payload.
    module Reverse
      autoload :Comm, 'msf/core/handler/reverse/comm'
      autoload :SSL, 'msf/core/handler/reverse/ssl'

      def initialize(info = {})
        super

        register_options(
          [
            Msf::OptAddressOrHostname.new('LHOST', [true, 'The listen address (an interface may be specified)']),
            Opt::LPORT(4444)
          ], Msf::Handler::Reverse)

        register_advanced_options(
          [
            OptPort.new('ReverseListenerBindPort', [false, 'The port to bind to on the local system if different from LPORT']),
            OptBool.new('ReverseAllowProxy', [ true, 'Allow reverse tcp even with Proxies specified. Connect back will NOT go through proxy but directly to LHOST', false]),
          ], Msf::Handler::Reverse
        )
      end

      def is_loopback_address?(address)
        begin
           a = IPAddr.new(address.to_s)
           return true if IPAddr.new('127.0.0.1/8') === a
           return true if IPAddr.new('::1') === a
        rescue
        end
        false
      end

      # A list of addresses to attempt to bind, in preferred order.
      #
      # @return [Array<String>] a two-element array. The first element will be
      #   the address that `datastore['LHOST']` resolves to, the second will
      #   be the INADDR_ANY address for IPv4 or IPv6, depending on the version
      #   of the first element.
      def bind_addresses
        if not datastore['ReverseListenerBindAddress'].to_s.empty?
          # ReverseListenerBindAddress is explicitly set; use it directly without
          # resolving LHOST (LHOST may be a tunnel hostname not locally resolvable).
          bind_addr = datastore['ReverseListenerBindAddress']
          any = Rex::Socket.is_ipv6?(bind_addr) ? '::0' : '0.0.0.0'
          return [ Rex::Socket.addr_atoi(bind_addr) == 0 ? any : bind_addr ]
        end

        # No ReverseListenerBindAddress set -- resolve LHOST to determine the
        # bind address and whether to use IPv4 or IPv6 ANY as fallback.
        begin
          addr_nbo = Rex::Socket.resolv_nbo(datastore['LHOST'])
        rescue StandardError
          print_warning("LHOST '#{datastore['LHOST']}' is not locally resolvable. Binding to 0.0.0.0. Set ReverseListenerBindAddress to override.")
          return ['0.0.0.0']
        end
        addr = Rex::Socket.addr_ntoa(addr_nbo)

        # First attempt to bind LHOST. If that fails, the user probably has
        # something else listening on that interface. Try again with ANY_ADDR.
        any = Rex::Socket.is_ipv4?(addr) ? '0.0.0.0' : '::0'

        if is_loopback_address?(addr)
          print_warning("You are binding to a loopback address by setting LHOST to #{addr}. Did you want ReverseListenerBindAddress?")
        end

        [addr, any]
      end

      # @return [Integer]
      def bind_port
        port = datastore['ReverseListenerBindPort'].to_i
        (port > 0) ? port : datastore['LPORT'].to_i
      end

      #
      # Starts the listener but does not actually attempt
      # to accept a connection.  Throws socket exceptions
      # if it fails to start the listener.
      #
      def setup_handler
        if !datastore['Proxies'].blank? && !datastore['ReverseAllowProxy']
          raise RuntimeError, "TCP connect-back payloads cannot be used with Proxies. Use 'set ReverseAllowProxy true' to override this behaviour."
        end

        ex = false

        comm = select_comm
        local_port = bind_port

        bind_addresses.each do |ip|
          begin
            self.listener_sock = Rex::Socket::TcpServer.create(
              'LocalHost' => ip,
              'LocalPort' => local_port,
              'Comm'      => comm,
              'Context'   =>
              {
                'Msf'        => framework,
                'MsfPayload' => self,
                'MsfExploit' => assoc_exploit
              })
          rescue
            ex = $!
            print_error("Handler failed to bind to #{ip}:#{local_port}:- #{comm} -")
          else
            ex = false
            via = via_string(self.listener_sock.client) if self.listener_sock.respond_to?(:client)
            print_status("Started #{human_name} handler on #{ip}:#{local_port} #{via}")
            break
          end
        end
        raise ex if (ex)
      end
    end
  end
end
