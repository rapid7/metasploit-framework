require 'logger'
require 'optparse'
require 'yaml'
require 'erb'

module Thin
  # CLI runner.
  # Parse options and send command to the correct Controller.
  class Runner
    COMMANDS            = %w(start stop restart config)
    LINUX_ONLY_COMMANDS = %w(install)

    # Commands that wont load options from the config file
    CONFIGLESS_COMMANDS = %w(config install)

    # Parsed options
    attr_accessor :options

    # Name of the command to be runned.
    attr_accessor :command

    # Arguments to be passed to the command.
    attr_accessor :arguments

    # Return all available commands
    def self.commands
      commands  = COMMANDS
      commands += LINUX_ONLY_COMMANDS if Thin.linux?
      commands
    end

    def initialize(argv)
      @argv = argv

      # Default options values
      @options = {
        :chdir                => Dir.pwd,
        :environment          => ENV['RACK_ENV'] || 'development',
        :address              => '0.0.0.0',
        :port                 => Server::DEFAULT_PORT,
        :timeout              => Server::DEFAULT_TIMEOUT,
        :log                  => File.join(Dir.pwd, 'log/thin.log'),
        :pid                  => 'tmp/pids/thin.pid',
        :max_conns            => Server::DEFAULT_MAXIMUM_CONNECTIONS,
        :max_persistent_conns => Server::DEFAULT_MAXIMUM_PERSISTENT_CONNECTIONS,
        :require              => [],
        :wait                 => Controllers::Cluster::DEFAULT_WAIT_TIME,
        :threadpool_size      => 20
      }

      parse!
    end

    def parser
      # NOTE: If you add an option here make sure the key in the +options+ hash is the
      # same as the name of the command line option.
      # +option+ keys are used to build the command line to launch other processes,
      # see <tt>lib/thin/command.rb</tt>.
      @parser ||= OptionParser.new do |opts|
        opts.banner = "Usage: thin [options] #{self.class.commands.join('|')}"

        opts.separator ""
        opts.separator "Server options:"

        opts.on("-a", "--address HOST", "bind to HOST address " +
                                        "(default: #{@options[:address]})")             { |host| @options[:address] = host }
        opts.on("-p", "--port PORT", "use PORT (default: #{@options[:port]})")          { |port| @options[:port] = port.to_i }
        opts.on("-S", "--socket FILE", "bind to unix domain socket")                    { |file| @options[:socket] = file }
        opts.on("-y", "--swiftiply [KEY]", "Run using swiftiply")                       { |key| @options[:swiftiply] = key }
        opts.on("-A", "--adapter NAME", "Rack adapter to use (default: autodetect)",
                                        "(#{Rack::ADAPTERS.map{|(a,b)|a}.join(', ')})") { |name| @options[:adapter] = name }
        opts.on("-R", "--rackup FILE", "Load a Rack config file instead of " +
                                       "Rack adapter")                                  { |file| @options[:rackup] = file }
        opts.on("-c", "--chdir DIR", "Change to dir before starting")                   { |dir| @options[:chdir] = File.expand_path(dir) }
        opts.on(      "--stats PATH", "Mount the Stats adapter under PATH")             { |path| @options[:stats] = path }

        opts.separator ""
        opts.separator "SSL options:"

        opts.on(      "--ssl", "Enables SSL")                                           { @options[:ssl] = true }
        opts.on(      "--ssl-key-file PATH", "Path to private key")                     { |path| @options[:ssl_key_file] = path }
        opts.on(      "--ssl-cert-file PATH", "Path to certificate")                    { |path| @options[:ssl_cert_file] = path }
        opts.on(      "--ssl-disable-verify", "Disables (optional) client cert requests") { @options[:ssl_disable_verify] = true }
        opts.on(      "--ssl-version VERSION", "TLSv1, TLSv1_1, TLSv1_2")               { |version| @options[:ssl_version] = version }
        opts.on(      "--ssl-cipher-list STRING", "Example: HIGH:!ADH:!RC4:-MEDIUM:-LOW:-EXP:-CAMELLIA") { |cipher| @options[:ssl_cipher_list] = cipher }

        opts.separator ""
        opts.separator "Adapter options:"
        opts.on("-e", "--environment ENV", "Framework environment " +
                                           "(default: #{@options[:environment]})")      { |env| @options[:environment] = env }
        opts.on(      "--prefix PATH", "Mount the app under PATH (start with /)")       { |path| @options[:prefix] = path }

        unless Thin.win? # Daemonizing not supported on Windows
          opts.separator ""
          opts.separator "Daemon options:"

          opts.on("-d", "--daemonize", "Run daemonized in the background")              { @options[:daemonize] = true }
          opts.on("-l", "--log FILE", "File to redirect output " +
                                      "(default: #{@options[:log]})")                   { |file| @options[:log] = file }
          opts.on("-P", "--pid FILE", "File to store PID " +
                                      "(default: #{@options[:pid]})")                   { |file| @options[:pid] = file }
          opts.on("-u", "--user NAME", "User to run daemon as (use with -g)")           { |user| @options[:user] = user }
          opts.on("-g", "--group NAME", "Group to run daemon as (use with -u)")         { |group| @options[:group] = group }
          opts.on(      "--tag NAME", "Additional text to display in process listing")  { |tag| @options[:tag] = tag }

          opts.separator ""
          opts.separator "Cluster options:"

          opts.on("-s", "--servers NUM", "Number of servers to start")                  { |num| @options[:servers] = num.to_i }
          opts.on("-o", "--only NUM", "Send command to only one server of the cluster") { |only| @options[:only] = only.to_i }
          opts.on("-C", "--config FILE", "Load options from config file")               { |file| @options[:config] = file }
          opts.on(      "--all [DIR]", "Send command to each config files in DIR")      { |dir| @options[:all] = dir } if Thin.linux?
          opts.on("-O", "--onebyone", "Restart the cluster one by one (only works with restart command)") { @options[:onebyone] = true }
          opts.on("-w", "--wait NUM", "Maximum wait time for server to be started in seconds (use with -O)") { |time| @options[:wait] = time.to_i }
        end

        opts.separator ""
        opts.separator "Tuning options:"

        opts.on("-b", "--backend CLASS", "Backend to use, full classname")              { |name| @options[:backend] = name }
        opts.on("-t", "--timeout SEC", "Request or command timeout in sec " +
                                       "(default: #{@options[:timeout]})")              { |sec| @options[:timeout] = sec.to_i }
        opts.on("-f", "--force", "Force the execution of the command")                  { @options[:force] = true }
        opts.on(      "--max-conns NUM", "Maximum number of open file descriptors " +
                                         "(default: #{@options[:max_conns]})",
                                         "Might require sudo to set higher than 1024")  { |num| @options[:max_conns] = num.to_i } unless Thin.win?
        opts.on(      "--max-persistent-conns NUM",
                                       "Maximum number of persistent connections",
                                       "(default: #{@options[:max_persistent_conns]})") { |num| @options[:max_persistent_conns] = num.to_i }
        opts.on(      "--threaded", "Call the Rack application in threads " +
                                    "[experimental]")                                   { @options[:threaded] = true }
        opts.on(      "--threadpool-size NUM", "Sets the size of the EventMachine threadpool.",
                                       "(default: #{@options[:threadpool_size]})") { |num| @options[:threadpool_size] = num.to_i }
        opts.on(      "--no-epoll", "Disable the use of epoll")                         { @options[:no_epoll] = true } if Thin.linux?

        opts.separator ""
        opts.separator "Common options:"

        opts.on_tail("-r", "--require FILE", "require the library")                     { |file| @options[:require] << file }
        opts.on_tail("-q", "--quiet", "Silence all logging")                            { @options[:quiet] = true }
        opts.on_tail("-D", "--debug", "Enable debug logging")                           { @options[:debug] = true }
        opts.on_tail("-V", "--trace", "Set tracing on (log raw request/response)")      { @options[:trace] = true }
        opts.on_tail("-h", "--help", "Show this message")                               { puts opts; exit }
        opts.on_tail('-v', '--version', "Show version")                                 { puts Thin::SERVER; exit }
      end
    end

    # Parse the options.
    def parse!
      parser.parse! @argv
      @command   = @argv.shift
      @arguments = @argv
    end

    # Parse the current shell arguments and run the command.
    # Exits on error.
    def run!
      if self.class.commands.include?(@command)
        run_command
      elsif @command.nil?
        puts "Command required"
        puts @parser
        exit 1
      else
        abort "Unknown command: #{@command}. Use one of #{self.class.commands.join(', ')}"
      end
    end

    # Send the command to the controller: single instance or cluster.
    def run_command
      load_options_from_config_file! unless CONFIGLESS_COMMANDS.include?(@command)

      # PROGRAM_NAME is relative to the current directory, so make sure
      # we store and expand it before changing directory.
      Command.script = File.expand_path($PROGRAM_NAME)

      # Change the current directory ASAP so that all relative paths are
      # relative to this one.
      Dir.chdir(@options[:chdir]) unless CONFIGLESS_COMMANDS.include?(@command)

      @options[:require].each { |r| ruby_require r }

      # Setup the logger
      if @options[:quiet]
        Logging.silent = true
      else
        Logging.level = Logger::DEBUG if @options[:debug]
      end

      if @options[:trace]
        # Trace raw requests/responses
        Logging.trace_logger = Logging.logger
      end

      controller = case
      when cluster? then Controllers::Cluster.new(@options)
      when service? then Controllers::Service.new(@options)
      else               Controllers::Controller.new(@options)
      end

      if controller.respond_to?(@command)
        begin
          controller.send(@command, *@arguments)
        rescue RunnerError => e
          abort e.message
        end
      else
        abort "Invalid options for command: #{@command}"
      end
    end

    # +true+ if we're controlling a cluster.
    def cluster?
      @options[:only] || @options[:servers] || @options[:config]
    end

    # +true+ if we're acting a as system service.
    def service?
      @options.has_key?(:all) || @command == 'install'
    end

    private
      def load_options_from_config_file!
        if file = @options.delete(:config)
          YAML.load(ERB.new(File.read(file)).result).each { |key, value| @options[key.to_sym] = value }
        end
      end

      def ruby_require(file)
        if File.extname(file) == '.ru'
          warn 'WARNING: Use the -R option to load a Rack config file'
          @options[:rackup] = file
        else
          require file
        end
      end
  end
end
