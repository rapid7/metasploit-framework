# -*- coding: binary -*-
require 'rex/socket'
require 'net/ssh/ruby_compat'
require 'net/ssh/proxy/errors'

module Net
  module SSH
    module Proxy

      # An implementation of a SOCKS5 proxy. To use it, instantiate it, then
      # pass the instantiated object via the :proxy key to Net::SSH.start:
      #
      #   require 'net/ssh/proxy/socks5'
      #
      #   proxy = Net::SSH::Proxy::SOCKS5.new('proxy.host', proxy_port,
      #     :user => 'user', :password => "password")
      #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
      #     ...
      #   end
      class SOCKS5
        # The SOCKS protocol version used by this class
        VERSION = 5

        # The SOCKS authentication type for requests without authentication
        METHOD_NO_AUTH = 0

        # The SOCKS authentication type for requests via username/password
        METHOD_PASSWD = 2

        # The SOCKS authentication type for when there are no supported
        # authentication methods.
        METHOD_NONE = 0xFF

        # The SOCKS packet type for requesting a proxy connection.
        CMD_CONNECT = 1

        # The SOCKS address type for connections via IP address.
        ATYP_IPV4 = 1

        # The SOCKS address type for connections via domain name.
        ATYP_DOMAIN = 3

        # The SOCKS response code for a successful operation.
        SUCCESS = 0

        # The proxy's host name or IP address
        attr_reader :proxy_host

        # The proxy's port number
        attr_reader :proxy_port

        # The map of options given at initialization
        attr_reader :options

        # Create a new proxy connection to the given proxy host and port.
        # Optionally, :user and :password options may be given to
        # identify the username and password with which to authenticate.
        def initialize(proxy_host, proxy_port=1080, options={})
          @proxy_host = proxy_host
          @proxy_port = proxy_port
          @options = options
        end

        # Return a new socket connected to the given host and port via the
        # proxy that was requested when the socket factory was instantiated.
        def open(host, port)
          socket = Rex::Socket::Tcp.create(
            'PeerHost' => proxy_host,
            'PeerPort' => proxy_port,
            'Context'  => {
               'Msf'        => options[:msframework],
               'MsfExploit' => options[:msfmodule]
            }
          )
          # Tell MSF to automatically close this socket on error or completion...
        # This prevents resource leaks.
        options[:msfmodule].add_socket(@socket) if options[:msfmodule]

          methods = [METHOD_NO_AUTH]
          methods << METHOD_PASSWD if options[:user]

          packet = [VERSION, methods.size, *methods].pack("C*")
          socket.send packet, 0

          version, method = socket.recv(2).unpack("CC")
          if version != VERSION
            socket.close
            raise Net::SSH::Proxy::Error, "invalid SOCKS version (#{version})"
          end

          if method == METHOD_NONE
            socket.close
            raise Net::SSH::Proxy::Error, "no supported authorization methods"
          end

          negotiate_password(socket) if method == METHOD_PASSWD

          packet = [VERSION, CMD_CONNECT, 0].pack("C*")

          if host =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/
            packet << [ATYP_IPV4, $1.to_i, $2.to_i, $3.to_i, $4.to_i].pack("C*")
          else
            packet << [ATYP_DOMAIN, host.length, host].pack("CCA*")
          end

          packet << [port].pack("n")
          socket.send packet, 0

          version, reply, = socket.recv(4).unpack("C*")
          len = socket.recv(1).getbyte(0)
          socket.recv(len + 2)

          unless reply == SUCCESS
            socket.close
            raise ConnectError, "#{reply}"
          end

          return socket
        end

        private

          # Simple username/password negotiation with the SOCKS5 server.
          def negotiate_password(socket)
            packet = [0x01, options[:user].length, options[:user],
              options[:password].length, options[:password]].pack("CCA*CA*")
            socket.send packet, 0

            version, status = socket.recv(2).unpack("CC")

            if status != SUCCESS
              socket.close
              raise UnauthorizedError, "could not authorize user"
            end
          end
      end

    end
  end
end
