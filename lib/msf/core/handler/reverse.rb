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
            Opt::LHOST,
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
        port > 0 ? port : datastore['LPORT'].to_i
      end

    end
  end
end
