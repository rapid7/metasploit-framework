require 'yaml'

module Thin
  # Error raised that will abort the process and print not backtrace.
  class RunnerError < RuntimeError; end
  
  # Raised when a mandatory option is missing to run a command.
  class OptionRequired < RunnerError
    def initialize(option)
      super("#{option} option required")
    end
  end
  
  # Raised when an option is not valid.
  class InvalidOption < RunnerError; end
  
  # Build and control Thin servers.
  # Hey Controller pattern is not only for web apps yo!
  module Controllers  
    # Controls one Thin server.
    # Allow to start, stop, restart and configure a single thin server.
    class Controller
      include Logging
    
      # Command line options passed to the thin script
      attr_accessor :options
    
      def initialize(options)
        @options = options
        
        if @options[:socket]
          @options.delete(:address)
          @options.delete(:port)
        end
      end
    
      def start
        # Constantize backend class
        @options[:backend] = eval(@options[:backend], TOPLEVEL_BINDING) if @options[:backend]

        server = Server.new(@options[:socket] || @options[:address], # Server detects kind of socket
                            @options[:port],                         # Port ignored on UNIX socket
                            @options)
        
        # Set options
        server.pid_file                       = @options[:pid]
        server.log_file                       = @options[:log]
        server.timeout                        = @options[:timeout]
        server.maximum_connections            = @options[:max_conns]
        server.maximum_persistent_connections = @options[:max_persistent_conns]
        server.threaded                       = @options[:threaded]
        server.no_epoll                       = @options[:no_epoll] if server.backend.respond_to?(:no_epoll=)
        server.threadpool_size                = @options[:threadpool_size] if server.threaded?

        # ssl support
        if @options[:ssl]
          server.ssl = true
          server.ssl_options = { :private_key_file => @options[:ssl_key_file], :cert_chain_file => @options[:ssl_cert_file], :verify_peer => !@options[:ssl_disable_verify], :ssl_version => @options[:ssl_version], :cipher_list => @options[:ssl_cipher_list]}
        end

        # Detach the process, after this line the current process returns
        server.daemonize if @options[:daemonize]

        # +config+ must be called before changing privileges since it might require superuser power.
        server.config
        
        server.change_privilege @options[:user], @options[:group] if @options[:user] && @options[:group]

        # If a Rack config file is specified we eval it inside a Rack::Builder block to create
        # a Rack adapter from it. Or else we guess which adapter to use and load it.
        if @options[:rackup]
          server.app = load_rackup_config
        else
          server.app = load_adapter
        end

        # If a prefix is required, wrap in Rack URL mapper
        server.app = Rack::URLMap.new(@options[:prefix] => server.app) if @options[:prefix]

        # If a stats URL is specified, wrap in Stats adapter
        server.app = Stats::Adapter.new(server.app, @options[:stats]) if @options[:stats]

        # Register restart procedure which just start another process with same options,
        # so that's why this is done here.
        server.on_restart { Command.run(:start, @options) }

        server.start
      end
    
      def stop
        raise OptionRequired, :pid unless @options[:pid]
      
        tail_log(@options[:log]) do
          if Server.kill(@options[:pid], @options[:force] ? 0 : (@options[:timeout] || 60))
            wait_for_file :deletion, @options[:pid]
          end
        end
      end
    
      def restart
        raise OptionRequired, :pid unless @options[:pid]
        
        tail_log(@options[:log]) do
          if Server.restart(@options[:pid])
            wait_for_file :creation, @options[:pid]
          end
        end
      end
    
      def config
        config_file = @options.delete(:config) || raise(OptionRequired, :config)

        # Stringify keys
        @options.keys.each { |o| @options[o.to_s] = @options.delete(o) }

        File.open(config_file, 'w') { |f| f << @options.to_yaml }
        log_info "Wrote configuration to #{config_file}"
      end
      
      protected
        # Wait for a pid file to either be created or deleted.
        def wait_for_file(state, file)
          Timeout.timeout(@options[:timeout] || 30) do
            case state
            when :creation then sleep 0.1 until File.exist?(file)
            when :deletion then sleep 0.1 while File.exist?(file)
            end
          end
        end
        
        # Tail the log file of server +number+ during the execution of the block.        
        def tail_log(log_file)
          if log_file
            tail_thread = tail(log_file)
            yield
            tail_thread.kill
          else
            yield
          end
        end
        
        # Acts like GNU tail command. Taken from Rails.
        def tail(file)
          cursor = File.exist?(file) ? File.size(file) : 0
          last_checked = Time.now
          tail_thread = Thread.new do
            Thread.pass until File.exist?(file)
            File.open(file, 'r') do |f|
              loop do
                f.seek cursor
                if f.mtime > last_checked
                  last_checked = f.mtime
                  contents = f.read
                  cursor += contents.length
                  print contents
                  STDOUT.flush
                end
                sleep 0.1
              end
            end
          end
          sleep 1 if File.exist?(file) # HACK Give the thread a little time to open the file
          tail_thread
        end

      private
        def load_adapter
          adapter = @options[:adapter] || Rack::Adapter.guess(@options[:chdir])
          log_info "Using #{adapter} adapter"
          Rack::Adapter.for(adapter, @options)
        rescue Rack::AdapterNotFound => e
          raise InvalidOption, e.message
        end
        
        def load_rackup_config
          ENV['RACK_ENV'] = @options[:environment]
          case @options[:rackup]
          when /\.rb$/
            Kernel.load(@options[:rackup])
            Object.const_get(File.basename(@options[:rackup], '.rb').capitalize.to_sym)
          when /\.ru$/
            Rack::Adapter.load(@options[:rackup])
          else
            raise "Invalid rackup file.  please specify either a .ru or .rb file"
          end
        end
    end
  end
end
