require 'optparse'

module Rack
  class Server
    class Options
      def parse!(args)
        options = {}
        opt_parser = OptionParser.new("", 24, '  ') do |opts|
          opts.banner = "Usage: rackup [ruby options] [rack options] [rackup config]"

          opts.separator ""
          opts.separator "Ruby options:"

          lineno = 1
          opts.on("-e", "--eval LINE", "evaluate a LINE of code") { |line|
            eval line, TOPLEVEL_BINDING, "-e", lineno
            lineno += 1
          }

          opts.on("-d", "--debug", "set debugging flags (set $DEBUG to true)") {
            options[:debug] = true
          }
          opts.on("-w", "--warn", "turn warnings on for your script") {
            options[:warn] = true
          }

          opts.on("-I", "--include PATH",
                  "specify $LOAD_PATH (may be used more than once)") { |path|
            options[:include] = path.split(":")
          }

          opts.on("-r", "--require LIBRARY",
                  "require the library, before executing your script") { |library|
            options[:require] = library
          }

          opts.separator ""
          opts.separator "Rack options:"
          opts.on("-s", "--server SERVER", "serve using SERVER (webrick/mongrel)") { |s|
            options[:server] = s
          }

          opts.on("-o", "--host HOST", "listen on HOST (default: 0.0.0.0)") { |host|
            options[:Host] = host
          }

          opts.on("-p", "--port PORT", "use PORT (default: 9292)") { |port|
            options[:Port] = port
          }

          opts.on("-O", "--option NAME[=VALUE]", "pass VALUE to the server as option NAME. If no VALUE, sets it to true. Run '#{$0} -s SERVER -h' to get a list of options for SERVER") { |name|
            name, value = name.split('=', 2)
            value = true if value.nil?
            options[name.to_sym] = value
          }

          opts.on("-E", "--env ENVIRONMENT", "use ENVIRONMENT for defaults (default: development)") { |e|
            options[:environment] = e
          }

          opts.on("-D", "--daemonize", "run daemonized in the background") { |d|
            options[:daemonize] = d ? true : false
          }

          opts.on("-P", "--pid FILE", "file to store PID (default: rack.pid)") { |f|
            options[:pid] = ::File.expand_path(f)
          }

          opts.separator ""
          opts.separator "Common options:"

          opts.on_tail("-h", "-?", "--help", "Show this message") do
            puts opts
            puts handler_opts(options)

            exit
          end

          opts.on_tail("--version", "Show version") do
            puts "Rack #{Rack.version} (Release: #{Rack.release})"
            exit
          end
        end

        begin
          opt_parser.parse! args
        rescue OptionParser::InvalidOption => e
          warn e.message
          abort opt_parser.to_s
        end

        options[:config] = args.last if args.last
        options
      end

      def handler_opts(options)
        begin
          info = []
          server = Rack::Handler.get(options[:server]) || Rack::Handler.default(options)
          if server && server.respond_to?(:valid_options)
            info << ""
            info << "Server-specific options for #{server.name}:"

            has_options = false
            server.valid_options.each do |name, description|
              next if name.to_s.match(/^(Host|Port)[^a-zA-Z]/) # ignore handler's host and port options, we do our own.
              info << "  -O %-21s %s" % [name, description]
              has_options = true
            end
            return "" if !has_options
          end
          info.join("\n")
        rescue NameError
          return "Warning: Could not find handler specified (#{options[:server] || 'default'}) to determine handler-specific options"
        end
      end
    end

    # Start a new rack server (like running rackup). This will parse ARGV and
    # provide standard ARGV rackup options, defaulting to load 'config.ru'.
    #
    # Providing an options hash will prevent ARGV parsing and will not include
    # any default options.
    #
    # This method can be used to very easily launch a CGI application, for
    # example:
    #
    #  Rack::Server.start(
    #    :app => lambda do |e|
    #      [200, {'Content-Type' => 'text/html'}, ['hello world']]
    #    end,
    #    :server => 'cgi'
    #  )
    #
    # Further options available here are documented on Rack::Server#initialize
    def self.start(options = nil)
      new(options).start
    end

    attr_writer :options

    # Options may include:
    # * :app
    #     a rack application to run (overrides :config)
    # * :config
    #     a rackup configuration file path to load (.ru)
    # * :environment
    #     this selects the middleware that will be wrapped around
    #     your application. Default options available are:
    #       - development: CommonLogger, ShowExceptions, and Lint
    #       - deployment: CommonLogger
    #       - none: no extra middleware
    #     note: when the server is a cgi server, CommonLogger is not included.
    # * :server
    #     choose a specific Rack::Handler, e.g. cgi, fcgi, webrick
    # * :daemonize
    #     if true, the server will daemonize itself (fork, detach, etc)
    # * :pid
    #     path to write a pid file after daemonize
    # * :Host
    #     the host address to bind to (used by supporting Rack::Handler)
    # * :Port
    #     the port to bind to (used by supporting Rack::Handler)
    # * :AccessLog
    #     webrick acess log options (or supporting Rack::Handler)
    # * :debug
    #     turn on debug output ($DEBUG = true)
    # * :warn
    #     turn on warnings ($-w = true)
    # * :include
    #     add given paths to $LOAD_PATH
    # * :require
    #     require the given libraries
    def initialize(options = nil)
      @options = options
      @app = options[:app] if options && options[:app]
    end

    def options
      @options ||= parse_options(ARGV)
    end

    def default_options
      {
        :environment => ENV['RACK_ENV'] || "development",
        :pid         => nil,
        :Port        => 9292,
        :Host        => "0.0.0.0",
        :AccessLog   => [],
        :config      => "config.ru"
      }
    end

    def app
      @app ||= begin
        if !::File.exist? options[:config]
          abort "configuration #{options[:config]} not found"
        end

        app, options = Rack::Builder.parse_file(self.options[:config], opt_parser)
        self.options.merge! options
        app
      end
    end

    def self.logging_middleware
      lambda { |server|
        server.server.name =~ /CGI/ ? nil : [Rack::CommonLogger, $stderr]
      }
    end

    def self.middleware
      @middleware ||= begin
        m = Hash.new {|h,k| h[k] = []}
        m["deployment"].concat [
          [Rack::ContentLength],
          [Rack::Chunked],
          logging_middleware
        ]
        m["development"].concat m["deployment"] + [[Rack::ShowExceptions], [Rack::Lint]]
        m
      end
    end

    def middleware
      self.class.middleware
    end

    def start &blk
      if options[:warn]
        $-w = true
      end

      if includes = options[:include]
        $LOAD_PATH.unshift(*includes)
      end

      if library = options[:require]
        require library
      end

      if options[:debug]
        $DEBUG = true
        require 'pp'
        p options[:server]
        pp wrapped_app
        pp app
      end

      # Touch the wrapped app, so that the config.ru is loaded before
      # daemonization (i.e. before chdir, etc).
      wrapped_app

      daemonize_app if options[:daemonize]
      write_pid if options[:pid]

      trap(:INT) do
        if server.respond_to?(:shutdown)
          server.shutdown
        else
          exit
        end
      end

      server.run wrapped_app, options, &blk
    end

    def server
      @_server ||= Rack::Handler.get(options[:server]) || Rack::Handler.default(options)
    end

    private
      def parse_options(args)
        options = default_options

        # Don't evaluate CGI ISINDEX parameters.
        # http://hoohoo.ncsa.uiuc.edu/cgi/cl.html
        args.clear if ENV.include?("REQUEST_METHOD")

        options.merge! opt_parser.parse!(args)
        options[:config] = ::File.expand_path(options[:config])
        ENV["RACK_ENV"] = options[:environment]
        options
      end

      def opt_parser
        Options.new
      end

      def build_app(app)
        middleware[options[:environment]].reverse_each do |middleware|
          middleware = middleware.call(self) if middleware.respond_to?(:call)
          next unless middleware
          klass = middleware.shift
          app = klass.new(app, *middleware)
        end
        app
      end

      def wrapped_app
        @wrapped_app ||= build_app app
      end

      def daemonize_app
        if RUBY_VERSION < "1.9"
          exit if fork
          Process.setsid
          exit if fork
          Dir.chdir "/"
          STDIN.reopen "/dev/null"
          STDOUT.reopen "/dev/null", "a"
          STDERR.reopen "/dev/null", "a"
        else
          Process.daemon
        end
      end

      def write_pid
        ::File.open(options[:pid], 'w'){ |f| f.write("#{Process.pid}") }
        at_exit { ::File.delete(options[:pid]) if ::File.exist?(options[:pid]) }
      end
  end
end
