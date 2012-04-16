module Thin
  # To be included in classes to allow some basic logging
  # that can be silenced (<tt>Logging.silent=</tt>) or made
  # more verbose.
  # <tt>Logging.debug=</tt>: log all error backtrace and messages
  #                          logged with +debug+.
  # <tt>Logging.trace=</tt>: log all raw request and response and
  #                          messages logged with +trace+.
  module Logging
    class << self
      attr_writer :trace, :debug, :silent
      
      def trace?;  !@silent && @trace  end
      def debug?;  !@silent && @debug  end
      def silent?;  @silent            end
    end
    
    # Global silencer methods
    def silent
      Logging.silent?
    end
    def silent=(value)
      Logging.silent = value
    end
    
    # Log a message to the console
    def log(msg)
      puts msg unless Logging.silent?
    end
    module_function :log
    public :log
    
    # Log a message to the console if tracing is activated
    def trace(msg=nil)
      log msg || yield if Logging.trace?
    end
    module_function :trace
    public :trace
    
    # Log a message to the console if debugging is activated
    def debug(msg=nil)
      log msg || yield if Logging.debug?
    end
    module_function :debug
    public :debug
    
    # Log an error backtrace if debugging is activated
    def log_error(e=$!)
      STDERR.print("#{e}\n\t" + e.backtrace.join("\n\t")) if Logging.debug?
    end
    module_function :log_error
    public :log_error
  end
end
