module Rex
  module Socket

    # This class exists to abuse the Proxy capabilities in the Net::SSH library to allow the use of Rex::Sockets
    # for the transport layer in Net::SSH. The SSHFactory object will respond to the #open method and create the
    # {Rex::Socket::Tcp}
    class SSHFactory

      # @!attribute msfraemwork
      #   @return [Object] The framework instance object
      attr_accessor :framework
      # @!attribute msfmodule
      #   @return [Object] The metasploit module this socket belongs to
      attr_accessor :msfmodule
      # @!attribute proxies
      #   @return [String] Any proxies to use for the connection
      attr_accessor :proxies

      def initialize(framework, msfmodule, proxies)
        @framework = framework
        @msfmodule   = msfmodule
        @proxies     = proxies
      end

      # Responds to the proxy setup routine Net::SSH will call when
      # initialising the Transport Layer. This will instead create our
      # {Rex::Socket::Tcp} and tie the socket back to the calling module
      # @param host [String] The host to open the connection to
      # @param port [Fixnum] the port to open the connection on
      # @param options [Hash] the options hash
      def open(host, port, options={})
        socket = Rex::Socket::Tcp.create(
          'PeerHost' => host,
          'PeerPort' => port,
          'Proxies' => proxies,
          'Context'  => {
            'Msf'          => framework,
            'MsfExploit'   => msfmodule
          }
        )
        socket
      end
    end
  end
end