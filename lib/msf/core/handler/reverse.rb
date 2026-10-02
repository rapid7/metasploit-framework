module Msf
  module Handler
    # Options and methods needed for all handlers that listen for a connection
    # from the payload.
    module Reverse
      autoload :Comm, 'msf/core/handler/reverse/comm'
      autoload :SSL, 'msf/core/handler/reverse/ssl'
      autoload :Bind, 'msf/core/handler/reverse/bind'

      include Msf::Handler::Reverse::Bind

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
