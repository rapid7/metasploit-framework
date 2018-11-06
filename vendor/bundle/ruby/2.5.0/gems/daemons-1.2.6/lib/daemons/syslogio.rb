# This is a simple class meant to allow using syslog through an IO-like object. Code
# borrowed from https://github.com/phemmer/ruby-syslogio
#
# The usage is simple:
#
#     require 'syslogio'
#     $stdout = SyslogIO.new("myapp", :local0, :info, $stdout)
#     $stderr = SyslogIO.new("myapp", :local0, :err, $stderr)
#     $stdout.puts "This is a message"
#     $stderr.puts "This is an error"
#     raise StandardError, 'This will get written through the SyslogIO for $stderr'

class Daemons::SyslogIO
  require 'syslog'

  # Indicates whether synchonous IO is enabled.
  # @return [Boolean]
  attr_reader :sync

  # @!visibility private
  def self.syslog_constant_sym(option)
    return unless option.is_a?(Symbol) or option.is_a?(String)
    option = option.to_s.upcase
    option = "LOG_#{option}" unless option[0..4] == 'LOG_'
    option = option.to_sym
    option
  end
  # @!visibility private
  def self.syslog_constant(option)
    return unless option = syslog_constant_sym(option)
    return Syslog.constants.include?(option) ? Syslog.const_get(option) : nil
  end
  # @!visibility private
  def self.syslog_facility(option)
    return unless option = syslog_constant_sym(option)
    return Syslog::Facility.constants.include?(option) ? Syslog.const_get(option) : nil
  end
  # @!visibility private
  def self.syslog_level(option)
    return unless option = syslog_constant_sym(option)
    return Syslog::Level.constants.include?(option) ? Syslog.const_get(option) : nil
  end
  # @!visibility private
  def self.syslog_option(option)
    return unless option = syslog_constant_sym(option)
    return Syslog::Option.constants.include?(option) ? Syslog.const_get(option) : nil
  end

  # Creates a new object.
  # You can have as many SyslogIO objects as you like. However because they all share the same syslog connection, some parameters are shared. The identifier shared among all SyslogIO objects, and is set to the value of the last one created. The Syslog options are merged together as a combination of all objects. The facility and level are distinct between each though.
  # If an IO object is provided as an argument, any text written to the SyslogIO object will also be passed through to that IO object.
  #
  # @param identifier [String] Identifier
  # @param facility [Fixnum<Syslog::Facility>] Syslog facility
  # @param level [Fixnum<Syslog::Level>] Syslog level
  # @param option [Fixnum<Syslog::Options>] Syslog option
  # @param passthrough [IO] IO passthrough
  def initialize(*options)
    options.each do |option|
      if option.is_a?(String)
        @ident = option
      elsif value = self.class.syslog_facility(option)
        @facility = value
      elsif value = self.class.syslog_level(option)
        @level = value
      elsif value = self.class.syslog_option(option)
        @options = 0 if @options.nil?
        @options |= value
      elsif option.is_a?(IO)
        @out = option
      else
        raise ArgumentError, "Unknown argument #{option.inspect}"
      end
    end

    @options ||= 0
    @ident ||= $0.sub(/.*\//, '')
    @facility ||= Syslog::LOG_USER
    @level ||= Syslog::LOG_INFO

    if Syslog.opened? then
      options = Syslog.options | @options
      @syslog = Syslog.reopen(@ident, options, @facility)
    else
      @syslog = Syslog.open(@ident, @options, @facility)
    end

    @subs = []
    @sync = false
    @buffer = ''

    at_exit { flush }
  end

  # Add a substitution rule
  #
  # These substitutions will be applied to each line before it is logged. This can be useful if some other gem is generating log content and you want to change the formatting.
  # @param regex [Regex]
  def sub_add(regex, replacement)
    @subs << [regex, replacement]
  end

  # Enable or disable synchronous IO (buffering).
  #
  # When false (default), output will be line buffered. For syslog this is optimal so the log entries are complete lines.
  def sync=(sync)
    if sync != true and sync != false then
      raise ArgumentError, "sync must be true or false"
    end
    @sync = sync
    if sync == true then
      flush
    end
  end

  # Write to syslog respecting the behavior of the {#sync} setting.
  def write(text)
    if @sync then
      syswrite(text)
    else
      text.split(/(\n)/).each do |line|
        @buffer = @buffer + line.to_s
        if line == "\n" then
          flush
        end
      end
    end
  end
  alias_method :<<, :write

  # Write to syslog directly, bypassing buffering if enabled.
  def syswrite(text)
    begin
      @out.syswrite(text) if @out and !@out.closed?
    rescue SystemCallError => e
    end

    text.split(/\n/).each do |line|
      @subs.each do |sub|
        line.sub!(sub[0], sub[1])
      end
      if line == '' or line.match(/^\s*$/) then
        next
      end
      Syslog.log(@facility | @level, line)
    end
    nil
  end

  # Immediately flush any buffered data
  def flush
    syswrite(@buffer)
    @buffer = ''
  end

  # Log at the debug level
  #
  # Shorthand for {#log}(text, Syslog::LOG_DEBUG)
  def debug(text)
    log(text, Syslog::LOG_DEBUG)
  end

  # Log at the info level
  #
  # Shorthand for {#log}(text, Syslog::LOG_INFO)
  def info(text)
    log(text, Syslog::LOG_INFO)
  end

  # Log at the notice level
  #
  # Shorthand for {#log}(text, Syslog::LOG_NOTICE)
  def notice(text)
    log(text, Syslog::LOG_NOTICE)
  end
  alias_method :notify, :notice

  # Log at the warning level
  #
  # Shorthand for {#log}(text, Syslog::LOG_WARNING)
  def warn(text)
    log(text, Syslog::LOG_WARNING)
  end

  # Log at the error level
  #
  # Shorthand for {#log}(text, Syslog::LOG_ERR)
  def error(text)
    log(text, Syslog::LOG_ERR)
  end

  # Log at the critical level
  #
  # Shorthand for {#log}(text, Syslog::LOG_CRIT)
  def crit(text)
    log(text, Syslog::LOG_CRIT)
  end
  alias_method :fatal, :crit

  # Log at the emergency level
  #
  # Shorthand for {#log}(text, Syslog::LOG_EMERG)
  def emerg(text)
    log(text, Syslog::LOG_EMERG)
  end

  # Log a complete line
  #
  # Similar to {#write} but appends a newline if not present.
  def puts(*texts)
    texts.each do |text|
      write(text.chomp + "\n")
    end
  end

  # Write a complete line at the specified log level
  #
  # Similar to {#puts} but allows changing the log level for just this one message
  def log(text, level = nil)
    if priority.nil? then
      write(text.chomp + "\n")
    else
      priority_bkup = @priority
      #TODO fix this to be less ugly. Temporarily setting an instance variable is evil
      @priority = priority
      write(text.chomp + "\n")
      @priority = priority_bkup
    end
  end

  # @!visibility private
  def noop(*args)
  end
  alias_method :reopen, :noop

  # false
  def isatty
    false
  end
end
