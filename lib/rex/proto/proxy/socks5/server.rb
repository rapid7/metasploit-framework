# -*- coding: binary -*-

require 'thread'
require 'rex/logging'
require 'rex/socket'
require 'rex/proto/proxy/socks5/server_client'

module Rex
module Proto
module Proxy

module Socks5
  #
  # A SOCKS5 proxy server.
  #
  class Server
    #
    # Create a new SOCKS5 server.
    #
    def initialize(opts={})
      @opts          = { 'ServerHost' => '0.0.0.0', 'ServerPort' => 1080 }
      @opts          = @opts.merge(opts)
      @server        = nil
      @clients       = ::Array.new
      @running       = false
      @server_thread = nil
    end

    #
    # Check if the server is running.
    #
    def is_running?
      return @running
    end

    #
    # Start the SOCKS5 server.
    #
    def start
      begin
        # create the servers main socket (ignore the context here because we don't want a remote bind)
        @server = Rex::Socket::TcpServer.create('LocalHost' => @opts['ServerHost'], 'LocalPort' => @opts['ServerPort'])
        # signal we are now running
        @running = true
        # start the servers main thread to pick up new clients
        @server_thread = Rex::ThreadFactory.spawn("SOCKS5ProxyServer", false) do
          while @running
            begin
              # accept the client connection
              sock = @server.accept
              # and fire off a new client instance to handle it
              ServerClient.new(self, sock, @opts).start
            rescue
              wlog("SOCKS5.start - server_thread - #{$!}")
            end
          end
        end
      rescue
        wlog("SOCKS5.start - #{$!}")
        return false
      end
      return true
    end

    #
    # Block while the server is running.
    #
    def join
      @server_thread.join if @server_thread
    end

    #
    # Stop the SOCKS5 server.
    #
    def stop
      if @running
        # signal we are no longer running
        @running = false
        # stop any clients we have (create a new client array as client.stop will delete from @clients)
        clients = @clients.dup
        clients.each do | client |
          client.stop
        end
        # close the server socket
        @server.close if @server
        # if the server thread did not terminate gracefully, kill it.
        @server_thread.kill if @server_thread and @server_thread.alive?
      end
      return !@running
    end

    def add_client(client)
      @clients << client
    end

    def remove_client(client)
      @clients.delete(client)
    end

    attr_reader :opts
  end
end
end
end
end
