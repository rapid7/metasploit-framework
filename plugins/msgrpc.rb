#
# This plugin provides an msf daemon interface that spawns a listener on a
# defined port (default 55552) and gives each connecting client its own
# console interface.  These consoles all share the same framework instance.
# Be aware that the console instance that spawns on the port is entirely
# unauthenticated, so realize that you have been warned.
#

require 'msf/core/rpc/v10/service'
require 'fileutils'

module Msf
  ###
  #
  # This class implements the msfd plugin interface.
  #
  ###
  class Plugin::MSGRPC < Msf::Plugin

    #
    # The default local hostname that the server listens on.
    #
    DefaultHost = '127.0.0.1'.freeze

    #
    # The default local port that the server listens on.
    #
    DefaultPort = 55552

    #
    # ServerPort
    #
    # 	The local port to listen on for connections.  The default is 55552
    #
    def initialize(framework, opts)
      super

      host = opts['ServerHost'] || DefaultHost
      port = opts['ServerPort'] || DefaultPort
      ssl = (opts['SSL'] && opts['SSL'].to_s =~ /^[ty]/i) ? true : false
      cert = opts['SSLCert']

      user = opts['User'] || 'msf'
      pass = opts['Pass'] || ::Rex::Text.rand_text_alphanumeric(8)
      uri = opts['URI'] || '/api'
      timeout = opts['TokenTimeout'] || 300

      print_status("MSGRPC Service:  #{host}:#{port} #{ssl ? ' (SSL)' : ''}")
      print_status("MSGRPC Username: #{user}")
      print_status("MSGRPC Password: #{pass}")

      self.server	= ::Msf::RPC::Service.new(framework, {
        host: host,
        port: port,
        ssl: ssl,
        cert: cert,
        uri: uri,
        tokens: {},
        token_timeout: timeout
      })

      server.add_user(user, pass)

      # If the run in foreground flag is not specified, then go ahead and fire
      # it off in a worker thread.
      unless opts['RunInForeground'] == true
        # Store a handle to the thread so we can kill it during
        # cleanup when we get unloaded.
        self.thread = Thread.new { run }
        framework.threads.register(thread, 'MetasploitRPCServer', true)
      end
    end

    #
    # Returns 'msgrpc'
    #
    def name
      'msgrpc'
    end

    #
    # Returns the plugin description.
    #
    def desc
      'Provides a MessagePack interface over HTTP'
    end

    #
    # The meat of the plugin, sets up handlers for requests
    #
    def run
      # Start the actual service
      server.start

      # Register
      framework.threads.register(Thread.current, 'MetasploitRPCServer', true)

      # Wait for the service to complete
      server.wait
    end

    #
    # Closes the listener service.
    #
    def cleanup
      server.stop if server
      thread.kill if thread
      self.server = nil
      super
    end

    #
    # The MSGRPC instance.
    #
    attr_accessor :server
    attr_accessor :thread, :users, :tokens

  end
end
