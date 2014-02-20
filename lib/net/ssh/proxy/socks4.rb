# -*- coding: binary -*-
require 'rex/socket'
require 'resolv'
require 'ipaddr'
require 'net/ssh/proxy/errors'

module Net
  module SSH
    module Proxy

      # An implementation of a SOCKS4 proxy. To use it, instantiate it, then
      # pass the instantiated object via the :proxy key to Net::SSH.start:
      #
      #   require 'net/ssh/proxy/socks4'
      #
      #   proxy = Net::SSH::Proxy::SOCKS4.new('proxy.host', proxy_port, :user => 'user')
      #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
      #     ...
      #   end
      class SOCKS4

        # The SOCKS protocol version used by this class
        VERSION = 4

        # The packet type for connection requests
        CONNECT = 1

        # The status code for a successful connection
        GRANTED = 90

        # The proxy's host name or IP address, as given to the constructor.
        attr_reader :proxy_host

        # The proxy's port number.
        attr_reader :proxy_port

        # The additional options that were given to the proxy's constructor.
        attr_reader :options

        # Create a new proxy connection to the given proxy host and port.
        # Optionally, a :user key may be given to identify the username
        # with which to authenticate.
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

          ip_addr = IPAddr.new(Resolv.getaddress(host))
          
          packet = [VERSION, CONNECT, port.to_i, ip_addr.to_i, options[:user]].pack("CCnNZ*")
          socket.send packet, 0

          version, status, port, ip = socket.recv(8).unpack("CCnN")
          if status != GRANTED
            socket.close
            raise ConnectError, "error connecting to proxy (#{status})"
          end

          return socket
        end

      end

    end
  end
end
