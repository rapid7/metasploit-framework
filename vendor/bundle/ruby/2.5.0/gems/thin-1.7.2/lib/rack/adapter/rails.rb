require 'cgi'

# Adapter to run a Rails app with any supported Rack handler.
# By default it will try to load the Rails application in the
# current directory in the development environment.
#
# Options:
#  root: Root directory of the Rails app
#  environment: Rails environment to run in (development [default], production or test)
#  prefix: Set the relative URL root.
#
# Based on http://fuzed.rubyforge.org/ Rails adapter
module Rack
  module Adapter
    class Rails
      FILE_METHODS = %w(GET HEAD).freeze

      def initialize(options = {})
        @root   = options[:root]        || Dir.pwd
        @env    = options[:environment] || 'development'
        @prefix = options[:prefix]

        load_application

        @rails_app = self.class.rack_based? ? ActionController::Dispatcher.new : CgiApp.new
        @file_app  = Rack::File.new(::File.join(RAILS_ROOT, "public"))
      end

      def load_application
        ENV['RAILS_ENV'] = @env

        require "#{@root}/config/environment"
        require 'dispatcher'

        if @prefix
          if ActionController::Base.respond_to?(:relative_url_root=)
            ActionController::Base.relative_url_root = @prefix # Rails 2.1.1
          else
            ActionController::AbstractRequest.relative_url_root = @prefix
          end
        end
      end

      def file_exist?(path)
        full_path = ::File.join(@file_app.root, Utils.unescape(path))
        ::File.file?(full_path) && ::File.readable_real?(full_path)
      end

      def call(env)
        path        = env['PATH_INFO'].chomp('/')
        method      = env['REQUEST_METHOD']
        cached_path = (path.empty? ? 'index' : path) + ActionController::Base.page_cache_extension

        if FILE_METHODS.include?(method)
          if file_exist?(path)              # Serve the file if it's there
            return @file_app.call(env)
          elsif file_exist?(cached_path)    # Serve the page cache if it's there
            env['PATH_INFO'] = cached_path
            return @file_app.call(env)
          end
        end

        # No static file, let Rails handle it
        @rails_app.call(env)
      end

      def self.rack_based?
        rails_version = ::Rails::VERSION
        return false if rails_version::MAJOR < 2
        return false if rails_version::MAJOR == 2 && rails_version::MINOR < 2
        return false if rails_version::MAJOR == 2 && rails_version::MINOR == 2 && rails_version::TINY < 3
        true # >= 2.2.3
      end

      protected
        # For Rails pre Rack (2.3)
        class CgiApp
          def call(env)
            request         = Request.new(env)
            response        = Response.new
            session_options = ActionController::CgiRequest::DEFAULT_SESSION_OPTIONS
            cgi             = CGIWrapper.new(request, response)

            Dispatcher.dispatch(cgi, session_options, response)

            response.finish
          end
        end

        class CGIWrapper < ::CGI
          def initialize(request, response, *args)
            @request  = request
            @response = response
            @args     = *args
            @input    = request.body

            super *args
          end

          def header(options = 'text/html')
            if options.is_a?(String)
              @response['Content-Type']     = options unless @response['Content-Type']
            else
              @response['Content-Length']   = options.delete('Content-Length').to_s if options['Content-Length']

              @response['Content-Type']     = options.delete('type') || "text/html"
              @response['Content-Type']    += '; charset=' + options.delete('charset') if options['charset']

              @response['Content-Language'] = options.delete('language') if options['language']
              @response['Expires']          = options.delete('expires') if options['expires']

              @response.status              = options.delete('Status') if options['Status']

              # Convert 'cookie' header to 'Set-Cookie' headers.
              # Because Set-Cookie header can appear more the once in the response body,
              # we store it in a line break seperated string that will be translated to
              # multiple Set-Cookie header by the handler.
              if cookie = options.delete('cookie')
                cookies = []

                case cookie
                  when Array then cookie.each { |c| cookies << c.to_s }
                  when Hash  then cookie.each { |_, c| cookies << c.to_s }
                  else            cookies << cookie.to_s
                end

                @output_cookies.each { |c| cookies << c.to_s } if @output_cookies

                @response['Set-Cookie'] = [@response['Set-Cookie'], cookies].compact
                # See http://groups.google.com/group/rack-devel/browse_thread/thread/e8759b91a82c5a10/a8dbd4574fe97d69?#a8dbd4574fe97d69
                if Thin.ruby_18?
                  @response['Set-Cookie'].flatten!
                else
                  @response['Set-Cookie'] = @response['Set-Cookie'].join("\n")
                end
              end

              options.each { |k, v| @response[k] = v }
            end

            ''
          end

          def params
            @params ||= @request.params
          end

          def cookies
            @request.cookies
          end

          def query_string
            @request.query_string
          end

          # Used to wrap the normal args variable used inside CGI.
          def args
            @args
          end

          # Used to wrap the normal env_table variable used inside CGI.
          def env_table
            @request.env
          end

          # Used to wrap the normal stdinput variable used inside CGI.
          def stdinput
            @input
          end

          def stdoutput
            STDERR.puts 'stdoutput should not be used.'
            @response.body
          end
      end
    end
  end
end
