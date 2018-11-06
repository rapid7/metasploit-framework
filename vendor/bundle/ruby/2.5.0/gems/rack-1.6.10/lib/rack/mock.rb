require 'uri'
require 'stringio'
require 'rack'
require 'rack/lint'
require 'rack/utils'
require 'rack/response'

module Rack
  # Rack::MockRequest helps testing your Rack application without
  # actually using HTTP.
  #
  # After performing a request on a URL with get/post/put/patch/delete, it
  # returns a MockResponse with useful helper methods for effective
  # testing.
  #
  # You can pass a hash with additional configuration to the
  # get/post/put/patch/delete.
  # <tt>:input</tt>:: A String or IO-like to be used as rack.input.
  # <tt>:fatal</tt>:: Raise a FatalWarning if the app writes to rack.errors.
  # <tt>:lint</tt>:: If true, wrap the application in a Rack::Lint.

  class MockRequest
    class FatalWarning < RuntimeError
    end

    class FatalWarner
      def puts(warning)
        raise FatalWarning, warning
      end

      def write(warning)
        raise FatalWarning, warning
      end

      def flush
      end

      def string
        ""
      end
    end

    DEFAULT_ENV = {
      "rack.version" => Rack::VERSION,
      "rack.input" => StringIO.new,
      "rack.errors" => StringIO.new,
      "rack.multithread" => true,
      "rack.multiprocess" => true,
      "rack.run_once" => false,
    }

    def initialize(app)
      @app = app
    end

    def get(uri, opts={})     request("GET", uri, opts)     end
    def post(uri, opts={})    request("POST", uri, opts)    end
    def put(uri, opts={})     request("PUT", uri, opts)     end
    def patch(uri, opts={})   request("PATCH", uri, opts)   end
    def delete(uri, opts={})  request("DELETE", uri, opts)  end
    def head(uri, opts={})    request("HEAD", uri, opts)    end
    def options(uri, opts={}) request("OPTIONS", uri, opts) end

    def request(method="GET", uri="", opts={})
      env = self.class.env_for(uri, opts.merge(:method => method))

      if opts[:lint]
        app = Rack::Lint.new(@app)
      else
        app = @app
      end

      errors = env["rack.errors"]
      status, headers, body  = app.call(env)
      MockResponse.new(status, headers, body, errors)
    ensure
      body.close if body.respond_to?(:close)
    end

    # For historical reasons, we're pinning to RFC 2396. It's easier for users
    # and we get support from ruby 1.8 to 2.2 using this method.
    def self.parse_uri_rfc2396(uri)
      @parser ||= defined?(URI::RFC2396_Parser) ? URI::RFC2396_Parser.new : URI
      @parser.parse(uri)
    end

    # Return the Rack environment used for a request to +uri+.
    def self.env_for(uri="", opts={})
      uri = parse_uri_rfc2396(uri)
      uri.path = "/#{uri.path}" unless uri.path[0] == ?/

      env = DEFAULT_ENV.dup

      env_with_encoding(env, opts, uri)

      env[SCRIPT_NAME] = opts[:script_name] || ""

      if opts[:fatal]
        env["rack.errors"] = FatalWarner.new
      else
        env["rack.errors"] = StringIO.new
      end

      if params = opts[:params]
        if env[REQUEST_METHOD] == "GET"
          params = Utils.parse_nested_query(params) if params.is_a?(String)
          params.update(Utils.parse_nested_query(env[QUERY_STRING]))
          env[QUERY_STRING] = Utils.build_nested_query(params)
        elsif !opts.has_key?(:input)
          opts["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
          if params.is_a?(Hash)
            if data = Utils::Multipart.build_multipart(params)
              opts[:input] = data
              opts["CONTENT_LENGTH"] ||= data.length.to_s
              opts["CONTENT_TYPE"] = "multipart/form-data; boundary=#{Utils::Multipart::MULTIPART_BOUNDARY}"
            else
              opts[:input] = Utils.build_nested_query(params)
            end
          else
            opts[:input] = params
          end
        end
      end

      empty_str = ""
      empty_str.force_encoding("ASCII-8BIT") if empty_str.respond_to? :force_encoding
      opts[:input] ||= empty_str
      if String === opts[:input]
        rack_input = StringIO.new(opts[:input])
      else
        rack_input = opts[:input]
      end

      rack_input.set_encoding(Encoding::BINARY) if rack_input.respond_to?(:set_encoding)
      env['rack.input'] = rack_input

      env["CONTENT_LENGTH"] ||= env["rack.input"].length.to_s

      opts.each { |field, value|
        env[field] = value  if String === field
      }

      env
    end

    if "<3".respond_to? :b
      def self.env_with_encoding(env, opts, uri)
        env[REQUEST_METHOD] = (opts[:method] ? opts[:method].to_s.upcase : "GET").b
        env["SERVER_NAME"] = (uri.host || "example.org").b
        env["SERVER_PORT"] = (uri.port ? uri.port.to_s : "80").b
        env[QUERY_STRING] = (uri.query.to_s).b
        env[PATH_INFO] = ((!uri.path || uri.path.empty?) ? "/" : uri.path).b
        env["rack.url_scheme"] = (uri.scheme || "http").b
        env["HTTPS"] = (env["rack.url_scheme"] == "https" ? "on" : "off").b
      end
    else
      def self.env_with_encoding(env, opts, uri)
        env[REQUEST_METHOD] = opts[:method] ? opts[:method].to_s.upcase : "GET"
        env["SERVER_NAME"] = uri.host || "example.org"
        env["SERVER_PORT"] = uri.port ? uri.port.to_s : "80"
        env[QUERY_STRING] = uri.query.to_s
        env[PATH_INFO] = (!uri.path || uri.path.empty?) ? "/" : uri.path
        env["rack.url_scheme"] = uri.scheme || "http"
        env["HTTPS"] = env["rack.url_scheme"] == "https" ? "on" : "off"
      end
    end
  end

  # Rack::MockResponse provides useful helpers for testing your apps.
  # Usually, you don't create the MockResponse on your own, but use
  # MockRequest.

  class MockResponse < Rack::Response
    # Headers
    attr_reader :original_headers

    # Errors
    attr_accessor :errors

    def initialize(status, headers, body, errors=StringIO.new(""))
      @original_headers = headers
      @errors           = errors.string if errors.respond_to?(:string)
      @body_string      = nil

      super(body, status, headers)
    end

    def =~(other)
      body =~ other
    end

    def match(other)
      body.match other
    end

    def body
      # FIXME: apparently users of MockResponse expect the return value of
      # MockResponse#body to be a string.  However, the real response object
      # returns the body as a list.
      #
      # See spec_showstatus.rb:
      #
      #   should "not replace existing messages" do
      #     ...
      #     res.body.should == "foo!"
      #   end
      super.join
    end

    def empty?
      [201, 204, 205, 304].include? status
    end
  end
end
