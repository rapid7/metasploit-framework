require 'net/ssh/verifiers/accept_new'

module Net
  module SSH
    module Verifiers

      # Basically the same as the AcceptNew verifier, but does not try to actually
      # verify a connection if the server is the localhost and the port is a
      # nonstandard port number. Those two conditions will typically mean the
      # connection is being tunnelled through a forwarded port, so the known-hosts
      # file will not be helpful (in general).
      class AcceptNewOrLocalTunnel < AcceptNew
        # Tries to determine if the connection is being tunnelled, and if so,
        # returns true. Otherwise, performs the standard strict verification.
        def verify(arguments)
          return true if tunnelled?(arguments)
          super
        end

        private

        # A connection is potentially being tunnelled if the port is not 22,
        # and the ip refers to the localhost.
        def tunnelled?(args)
          return false if args[:session].port == Net::SSH::Transport::Session::DEFAULT_PORT

          ip = args[:session].peer[:ip]
          return ip == "127.0.0.1" || ip == "::1"
        end
      end

    end
  end
end
