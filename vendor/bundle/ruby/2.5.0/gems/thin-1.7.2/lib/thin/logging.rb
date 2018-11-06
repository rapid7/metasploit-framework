require 'logger'

module Thin
  # To be included in classes to allow some basic logging
  # that can be silenced (<tt>Logging.silent=</tt>) or made
  # more verbose.
  # <tt>Logging.trace=</tt>:  log all raw request and response and
  #                           messages logged with +trace+.
  # <tt>Logging.silent=</tt>: silence all log all log messages
  #                           altogether.
  module Logging
    # Simple formatter which only displays the message.
    # Taken from ActiveSupport
    class SimpleFormatter < Logger::Formatter
      def call(severity, timestamp, progname, msg)
        "#{String === msg ? msg : msg.inspect}\n"
      end
    end

    @trace_logger = nil

    class << self
      attr_reader :logger
      attr_reader :trace_logger

      def trace=(enabled)
        if enabled
          @trace_logger ||= Logger.new(STDOUT)
        else
          @trace_logger = nil
        end
      end

      def trace?
        !@trace_logger.nil?
      end

      def silent=(shh)
        if shh
          @logger = nil
        else
          @logger ||= Logger.new(STDOUT)
        end
      end

      def silent?
        !@logger.nil?
      end

      def level
        @logger ? @logger.level : nil # or 'silent'
      end

      def level=(value)
        # If logging has been silenced, then re-enable logging
        @logger = Logger.new(STDOUT) if @logger.nil?
        @logger.level = value
      end

      # Allow user to specify a custom logger to use.
      # This object must respond to:
      # +level+, +level=+ and +debug+, +info+, +warn+, +error+, +fatal+
      def logger=(custom_logger)
        [ :level   ,
          :level=  ,
          :debug   ,
          :info    ,
          :warn    ,
          :error   ,
          :fatal   ,
          :unknown ,
        ].each do |method|
          if not custom_logger.respond_to?(method)
            raise ArgumentError, "logger must respond to #{method}"
          end
        end

        @logger = custom_logger
      end

      def trace_logger=(custom_tracer)
        [ :level   ,
          :level=  ,
          :debug   ,
          :info    ,
          :warn    ,
          :error   ,
          :fatal   ,
          :unknown ,
        ].each do |method|
          if not custom_tracer.respond_to?(method)
            raise ArgumentError, "trace logger must respond to #{method}"
          end
        end

        @trace_logger = custom_tracer
      end

      def log_msg(msg, level=Logger::INFO)
        return unless @logger
        @logger.add(level, msg)
      end

      def trace_msg(msg)
        return unless @trace_logger
        @trace_logger.info(msg)
      end

      # Provided for backwards compatibility.
      # Callers should be using the +level+ (on the +Logging+ module
      # or on the instance) to figure out what the log level is.
      def debug?
        self.level == Logger::DEBUG
      end
      def debug=(val)
        self.level = (val ? Logger::DEBUG : Logger::INFO)
      end

    end # module methods

    # Default logger to stdout.
    self.logger           = Logger.new(STDOUT)
    self.logger.level     = Logger::INFO
    self.logger.formatter = Logging::SimpleFormatter.new

    def silent
      Logging.silent?
    end

    def silent=(value)
      Logging.silent = value
    end

    # Log a message if tracing is activated
    def trace(msg=nil)
      Logging.trace_msg(msg) if msg
    end
    module_function :trace
    public :trace

    # Log a message at DEBUG level
    def log_debug(msg=nil)
      Logging.log_msg(msg || yield, Logger::DEBUG)
    end
    module_function :log_debug
    public :log_debug

    # Log a message at INFO level
    def log_info(msg)
      Logging.log_msg(msg || yield, Logger::INFO)
    end
    module_function :log_info
    public :log_info

    # Log a message at ERROR level (and maybe a backtrace)
    def log_error(msg, e=nil)
      log_msg = msg
      if e
        log_msg += ": #{e}\n\t" + e.backtrace.join("\n\t") + "\n"
      end
      Logging.log_msg(log_msg, Logger::ERROR)
    end
    module_function :log_error
    public :log_error

    # For backwards compatibility
    def log msg
      STDERR.puts('#log has been deprecated, please use the ' \
                  'log_level function instead (e.g. - log_info).')
      log_info(msg)
    end

  end
end
