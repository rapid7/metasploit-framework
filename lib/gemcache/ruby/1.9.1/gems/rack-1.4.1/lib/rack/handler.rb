module Rack
  # *Handlers* connect web servers with Rack.
  #
  # Rack includes Handlers for Thin, WEBrick, FastCGI, CGI, SCGI
  # and LiteSpeed.
  #
  # Handlers usually are activated by calling <tt>MyHandler.run(myapp)</tt>.
  # A second optional hash can be passed to include server-specific
  # configuration.
  module Handler
    def self.get(server)
      return unless server
      server = server.to_s

      unless @handlers.include? server
        load_error = try_require('rack/handler', server)
      end

      if klass = @handlers[server]
        klass.split("::").inject(Object) { |o, x| o.const_get(x) }
      else
        const_get(server)
      end

    rescue NameError => name_error
      raise load_error || name_error
    end

    def self.default(options = {})
      # Guess.
      if ENV.include?("PHP_FCGI_CHILDREN")
        # We already speak FastCGI
        options.delete :File
        options.delete :Port

        Rack::Handler::FastCGI
      elsif ENV.include?("REQUEST_METHOD")
        Rack::Handler::CGI
      else
        begin
          Rack::Handler::Thin
        rescue LoadError
          Rack::Handler::WEBrick
        end
      end
    end

    # Transforms server-name constants to their canonical form as filenames,
    # then tries to require them but silences the LoadError if not found
    #
    # Naming convention:
    #
    #   Foo # => 'foo'
    #   FooBar # => 'foo_bar.rb'
    #   FooBAR # => 'foobar.rb'
    #   FOObar # => 'foobar.rb'
    #   FOOBAR # => 'foobar.rb'
    #   FooBarBaz # => 'foo_bar_baz.rb'
    def self.try_require(prefix, const_name)
      file = const_name.gsub(/^[A-Z]+/) { |pre| pre.downcase }.
        gsub(/[A-Z]+[^A-Z]/, '_\&').downcase

      require(::File.join(prefix, file))
      nil
    rescue LoadError => error
      error
    end

    def self.register(server, klass)
      @handlers ||= {}
      @handlers[server.to_s] = klass.to_s
    end

    autoload :CGI, "rack/handler/cgi"
    autoload :FastCGI, "rack/handler/fastcgi"
    autoload :Mongrel, "rack/handler/mongrel"
    autoload :EventedMongrel, "rack/handler/evented_mongrel"
    autoload :SwiftipliedMongrel, "rack/handler/swiftiplied_mongrel"
    autoload :WEBrick, "rack/handler/webrick"
    autoload :LSWS, "rack/handler/lsws"
    autoload :SCGI, "rack/handler/scgi"
    autoload :Thin, "rack/handler/thin"

    register 'cgi', 'Rack::Handler::CGI'
    register 'fastcgi', 'Rack::Handler::FastCGI'
    register 'mongrel', 'Rack::Handler::Mongrel'
    register 'emongrel', 'Rack::Handler::EventedMongrel'
    register 'smongrel', 'Rack::Handler::SwiftipliedMongrel'
    register 'webrick', 'Rack::Handler::WEBrick'
    register 'lsws', 'Rack::Handler::LSWS'
    register 'scgi', 'Rack::Handler::SCGI'
    register 'thin', 'Rack::Handler::Thin'
  end
end
