# frozen_string_literal: true
require 'fileutils'

module YARD
  module Server
    module Commands
      # This is the base command class used to implement custom commands for
      # a server. A command will be routed to by the {Router} class and return
      # a Rack-style response.
      #
      # == Attribute Initializers
      # All attributes can be initialized via options passed into the {#initialize}
      # method. When creating a custom command, the {Adapter#options} will
      # automatically be mapped to attributes by the same name on your class.
      #
      #   class MyCommand < Base
      #     attr_accessor :myattr
      #   end
      #
      #   Adapter.new(libs, {:myattr => 'foo'}).start
      #
      #   # when a request comes in, cmd.myattr == 'foo'
      #
      # == Subclassing Notes
      # To implement a custom command, override the {#run} method, not {#call}.
      # In your implementation, you should set the body and status for requests.
      # See details in the +#run+ method documentation.
      #
      # Note that if your command deals directly with libraries, you should
      # consider subclassing the more specific {LibraryCommand} class instead.
      #
      # @abstract
      # @see #run
      class Base
        # @group Basic Command and Adapter Options

        # @return [Hash] the options passed to the command's constructor
        attr_accessor :command_options

        # @return [Adapter] the server adapter
        attr_accessor :adapter

        # @return [Boolean] whether to cache
        attr_accessor :caching

        # @group Attributes Set Per Request

        # @return [Rack::Request] request object
        attr_accessor :request

        # @return [String] the path after the command base URI
        attr_accessor :path

        # @return [Hash{String => String}] response headers
        attr_accessor :headers

        # @return [Numeric] status code. Defaults to 200 per request
        attr_accessor :status

        # @return [String] the response body. Defaults to empty string.
        attr_accessor :body

        # @group Instance Method Summary

        # Creates a new command object, setting attributes named by keys
        # in the options hash. After initialization, the options hash
        # is saved in {#command_options} for further inspection.
        #
        # @example Creating a Command
        #   cmd = DisplayObjectCommand.new(:caching => true, :library => mylib)
        #   cmd.library # => mylib
        #   cmd.command_options # => {:caching => true, :library => mylib}
        # @param [Hash] opts the options hash, saved to {#command_options}
        #   after initialization.
        def initialize(opts = {})
          opts.each do |key, value|
            send("#{key}=", value) if respond_to?("#{key}=")
          end
          self.command_options = opts
        end

        # The main method called by a router with a request object.
        #
        # @note This command should not be overridden by subclasses. Implement
        #   the callback method {#run} instead.
        # @param [Adapter Dependent] request the request object
        # @return [Array(Numeric,Hash,Array<String>)] a Rack-style response
        #   of status, headers, and body wrapped in an array.
        def call(request)
          self.request = request
          self.path ||= request.path_info[1..-1]
          self.headers = {'Content-Type' => 'text/html'}
          self.body = ''
          self.status = 200
          add_cache_control
          begin
            run
          rescue FinishRequest
            nil # noop
          rescue NotFoundError => e
            self.body = e.message if e.message != e.class.to_s
            not_found
          end

          # keep this to support commands setting status manually.
          not_found if status == 404

          [status, headers, body.is_a?(Array) ? body : [body]]
        end

        # @group Abstract Methods

        # Subclass this method to implement a custom command. This method
        # should set the {#status} and {#body}, and optionally modify the
        # {#headers}. Note that +#status+ defaults to 200.
        #
        # @example A custom command
        #   class ErrorCommand < Base
        #     def run
        #       self.body = 'ERROR! The System is down!'
        #       self.status = 500
        #       self.headers['Conten-Type'] = 'text/plain'
        #     end
        #   end
        #
        # @abstract
        # @return [void]
        def run
          raise NotImplementedError
        end

        protected

        # @group Helper Methods

        # Renders a specific object if provided, or a regular template rendering
        # if object is not provided.
        #
        # @todo This method is dependent on +#options+, it should be in {LibraryCommand}.
        # @param [CodeObjects::Base, nil] object calls {CodeObjects::Base#format} if
        #   an object is provided, or {Templates::Engine.render} if object is nil. Both
        #   receive +#options+ as an argument.
        # @return [String] the resulting output to display
        def render(object = nil)
          case object
          when CodeObjects::Base
            cache object.format(options)
          when nil
            cache Templates::Engine.render(options)
          else
            cache object
          end
        end

        # Override this method to implement custom caching mechanisms for
        #
        # @example Caching to memory
        #   $memory_cache = {}
        #   def cache(data)
        #     $memory_cache[path] = data
        #   end
        # @param [String] data the data to cache
        # @return [String] the same cached data (for chaining)
        # @see StaticCaching
        def cache(data)
          if caching && adapter.document_root
            path = File.join(adapter.document_root, request.path_info.sub(/\.html$/, '') + '.html')
            path = path.sub(%r{/\.html$}, '.html')
            FileUtils.mkdir_p(File.dirname(path))
            log.debug "Caching data to #{path}"
            File.open(path, 'wb') {|f| f.write(data) }
          end
          self.body = data
        end

        # Sets the body and headers for a 404 response. Does not modify the
        # body if already set.
        #
        # @return [void]
        def not_found
          self.status = 404
          return unless body.empty?
          self.body = "Not found: #{request.path}"
          headers['Content-Type'] = 'text/plain'
          headers['X-Cascade'] = 'pass'
          headers.delete('Cache-Control')
        end

        # Sets the headers and status code for a redirection to a given URL
        # @param [String] url the URL to redirect to
        # @raise [FinishRequest] causes the request to terminate.
        def redirect(url)
          headers['Location'] = url
          self.status = 302
          raise FinishRequest
        end

        private

        # Add a conservative cache control policy to reduce load on
        # requests served with "?1234567890" style timestamp query strings.
        def add_cache_control
          return if request.query_string.to_i == 0
          headers['Cache-Control'] = 'private, max-age=300'
        end
      end
    end
  end
end
