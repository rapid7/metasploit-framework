# frozen_string_literal: true
require 'rack'
require 'webrick/httputils'

module YARD
  module Server
    # This class wraps the {RackAdapter} into a Rack-compatible middleware.
    # See {#initialize} for a list of options to pass via Rack's +#use+ method.
    #
    # @note You must pass a +:libraries+ option to the RackMiddleware via +#use+. To
    #   read about how to return a list of libraries, see {LibraryVersion} or look
    #   at the example below.
    # @example Using the RackMiddleware in a Rack application
    #   libraries = {:mylib => [YARD::Server::LibraryVersion.new('mylib', nil, '/path/to/.yardoc')]}
    #   use YARD::Server::RackMiddleware, :libraries => libraries
    #
    class RackMiddleware
      # Creates a new Rack-based middleware for serving YARD documentation.
      #
      # @param app the next Rack middleware in the stack
      # @option opts [Hash{String=>Array<LibraryVersion>}] :libraries ({})
      #   the map of libraries to serve through the adapter. This option is *required*.
      # @option opts [Hash] :options ({}) a list of options to pass to the adapter.
      #   See {Adapter#options} for a list.
      # @option opts [Hash] :server_options ({}) a list of options to pass to the server.
      #   See {Adapter#server_options} for a list.
      def initialize(app, opts = {})
        args = [opts[:libraries] || {}, opts[:options] || {}, opts[:server_options] || {}]
        @app = app
        @adapter = RackAdapter.new(*args)
      end

      def call(env)
        status, headers, body = *@adapter.call(env)
        if status == 404
          @app.call(env)
        else
          [status, headers, body]
        end
      end
    end

    # A server adapter to respond to requests using the Rack server infrastructure.
    class RackAdapter < Adapter
      include WEBrick::HTTPUtils

      # Responds to Rack requests and builds a response with the {Router}.
      # @return [Array(Numeric,Hash,Array)] the Rack-style response
      def call(env)
        request = Rack::Request.new(env)
        request.path_info = unescape(request.path_info) # unescape things like %3F
        router.call(request)
      rescue StandardError => ex
        log.backtrace(ex)
        [500, {'Content-Type' => 'text/plain'},
          [ex.message + "\n" + ex.backtrace.join("\n")]]
      end

      # Starts the +Rack::Server+. This method will pass control to the server and
      # block.
      # @return [void]
      def start
        server = Rack::Server.new(server_options)
        server.instance_variable_set("@app", self)
        print_start_message(server)
        server.start
      end

      private

      def print_start_message(server)
        opts = server.default_options.merge(server.options)
        log.puts ">> YARD #{YARD::VERSION} documentation server at http://#{opts[:Host]}:#{opts[:Port]}"

        # Only happens for Mongrel
        return unless server.server.to_s == "Rack::Handler::Mongrel"
        log.puts ">> #{server.server.class_name} web server (running on Rack)"
        log.puts ">> Listening on #{opts[:Host]}:#{opts[:Port]}, CTRL+C to stop"
      end
    end
  end
end

# @private
class Rack::Request
  attr_accessor :version_supplied
  alias query params
  def xhr?; (env['HTTP_X_REQUESTED_WITH'] || "").casecmp("xmlhttprequest") == 0 end
end
