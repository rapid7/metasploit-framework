# -*- coding: binary -*-
require 'rex/socket'
require 'net/ssh/proxy/errors'

module Net; module SSH; module Proxy

  # An implementation of an HTTP proxy. To use it, instantiate it, then
  # pass the instantiated object via the :proxy key to Net::SSH.start:
  #
  #   require 'net/ssh/proxy/http'
  #
  #   proxy = Net::SSH::Proxy::HTTP.new('proxy.host', proxy_port)
  #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
  #     ...
  #   end
  #
  # If the proxy requires authentication, you can pass :user and :password
  # to the proxy's constructor:
  #
  #   proxy = Net::SSH::Proxy::HTTP.new('proxy.host', proxy_port,
  #      :user => "user", :password => "password")
  #
  # Note that HTTP digest authentication is not supported; Basic only at
  # this point.
  class HTTP

    # The hostname or IP address of the HTTP proxy.
    attr_reader :proxy_host

    # The port number of the proxy.
    attr_reader :proxy_port

    # The map of additional options that were given to the object at
    # initialization.
    attr_reader :options

    # Create a new socket factory that tunnels via the given host and
    # port. The +options+ parameter is a hash of additional settings that
    # can be used to tweak this proxy connection. Specifically, the following
    # options are supported:
    #
    # * :user => the user name to use when authenticating to the proxy
    # * :password => the password to use when authenticating
    def initialize(proxy_host, proxy_port=80, options={})
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

      socket.write "CONNECT #{host}:#{port} HTTP/1.0\r\n"

      if options[:user]
        credentials = ["#{options[:user]}:#{options[:password]}"].pack("m*").gsub(/\s/, "")
        socket.write "Proxy-Authorization: Basic #{credentials}\r\n"
      end

      socket.write "\r\n"

      resp = parse_response(socket)

      return socket if resp[:code] == 200

      socket.close
      raise ConnectError, resp.inspect
    end

    private

      def parse_response(socket)
        version, code, reason = socket.gets.chomp.split(/ /, 3)
        headers = {}

        while (line = socket.gets.chomp) != ""
          name, value = line.split(/:/, 2)
          headers[name.strip] = value.strip
        end

        if headers["Content-Length"]
          body = socket.read(headers["Content-Length"].to_i)
        end

        return { :version => version,
                 :code => code.to_i,
                 :reason => reason,
                 :headers => headers,
                 :body => body }
      end

  end

end; end; end
