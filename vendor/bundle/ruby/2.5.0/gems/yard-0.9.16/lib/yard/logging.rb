# encoding: utf-8
# frozen_string_literal: true
require 'logger'
require 'thread'

module YARD
  # Handles console logging for info, warnings and errors.
  # Uses the stdlib Logger class in Ruby for all the backend logic.
  class Logger < ::Logger
    # The list of characters displayed beside the progress bar to indicate
    # "movement".
    # @since 0.8.2
    PROGRESS_INDICATORS = %w(⣷ ⣯ ⣟ ⡿ ⢿ ⣻ ⣽ ⣾)

    # @return [IO] the IO object being logged to
    # @since 0.8.2
    def io; @logdev end
    def io=(pipe) @logdev = pipe end

    # @return [Boolean] whether backtraces should be shown (by default
    #   this is on).
    def show_backtraces; @show_backtraces || level == DEBUG end
    attr_writer :show_backtraces

    # @return [Boolean] whether progress indicators should be shown when
    #   logging CLIs (by default this is off).
    def show_progress
      return false if YARD.ruby18? # threading is too ineffective for progress support
      return false if YARD.windows? # windows has poor ANSI support
      return false unless io.tty? # no TTY support on IO
      return false unless level > INFO # no progress in verbose/debug modes
      @show_progress
    end
    attr_writer :show_progress

    # The logger instance
    # @return [Logger] the logger instance
    def self.instance(pipe = STDOUT)
      @logger ||= new(pipe)
    end

    # Creates a new logger
    def initialize(pipe, *args)
      super(pipe, *args)
      self.io = pipe
      self.show_backtraces = true
      self.show_progress = false
      self.level = WARN
      self.formatter = method(:format_log)
      self.warned = false
      @progress_indicator = 0
      @mutex = Mutex.new
      @progress_msg = nil
      @progress_last_update = Time.now
    end

    # Changes the debug level to DEBUG if $DEBUG is set
    # and writes a debugging message.
    def debug(*args)
      self.level = DEBUG if $DEBUG
      super
    end

    # Remembers when a warning occurs and writes a warning message.
    def warn(*args)
      self.warned = true
      super
    end
    attr_accessor :warned

    # Captures the duration of a block of code for benchmark analysis. Also
    # calls {#progress} on the message to display it to the user.
    #
    # @todo Implement capture storage for reporting of benchmarks
    # @param [String] msg the message to display
    # @param [Symbol, nil] nontty_log the level to log as if the output
    #   stream is not a TTY. Use +nil+ for no alternate logging.
    # @yield a block of arbitrary code to benchmark
    # @return [void]
    def capture(msg, nontty_log = :debug)
      progress(msg, nontty_log)
      yield
    ensure
      clear_progress
    end

    # Displays a progress indicator for a given message. This progress report
    # is only displayed on TTY displays, otherwise the message is passed to
    # the +nontty_log+ level.
    #
    # @param [String] msg the message to log
    # @param [Symbol, nil] nontty_log the level to log as if the output
    #   stream is not a TTY. Use +nil+ for no alternate logging.
    # @return [void]
    # @since 0.8.2
    def progress(msg, nontty_log = :debug)
      send(nontty_log, msg) if nontty_log
      return unless show_progress
      icon = ""
      if defined?(::Encoding)
        icon = PROGRESS_INDICATORS[@progress_indicator] + " "
      end
      @mutex.synchronize do
        print("\e[2K\e[?25l\e[1m#{icon}#{msg}\e[0m\r")
        @progress_msg = msg
        if Time.now - @progress_last_update > 0.2
          @progress_indicator += 1
          @progress_indicator %= PROGRESS_INDICATORS.size
          @progress_last_update = Time.now
        end
      end
      Thread.new do
        sleep(0.05)
        progress(msg + ".", nil) if @progress_msg == msg
      end
    end

    # Clears the progress indicator in the TTY display.
    # @return [void]
    # @since 0.8.2
    def clear_progress
      return unless show_progress
      print_no_newline("\e[?25h\e[2K")
      @progress_msg = nil
    end

    # Displays an unformatted line to the logger output stream, adding
    # a newline.
    # @param [String] msg the message to display
    # @return [void]
    # @since 0.8.2
    def puts(msg = '')
      print("#{msg}\n")
    end

    alias print_no_newline <<
    private :print_no_newline

    # Displays an unformatted line to the logger output stream.
    # @param [String] msg the message to display
    # @return [void]
    # @since 0.8.2
    def print(msg = '')
      clear_line
      print_no_newline(msg)
    end
    alias << print

    # Prints the backtrace +exc+ to the logger as error data.
    #
    # @param [Array<String>] exc the backtrace list
    # @param [Symbol] level_meth the level to log backtrace at
    # @return [void]
    def backtrace(exc, level_meth = :error)
      return unless show_backtraces
      send(level_meth, "#{exc.class.class_name}: #{exc.message}")
      send(level_meth, "Stack trace:" +
        exc.backtrace[0..5].map {|x| "\n\t#{x}" }.join + "\n")
    end

    # Warns that the Ruby environment does not support continuations. Applies
    # to JRuby, Rubinius and MacRuby. This warning will only display once
    # per Ruby process.
    #
    # @deprecated Continuations are no longer needed by YARD 0.8.0+.
    # @return [void]
    def warn_no_continuations
    end

    # Sets the logger level for the duration of the block
    #
    # @example
    #   log.enter_level(Logger::ERROR) do
    #     YARD.parse_string "def x; end"
    #   end
    # @param [Fixnum] new_level the logger level for the duration of the block.
    #   values can be found in Ruby's Logger class.
    # @yield the block with the logger temporarily set to +new_level+
    def enter_level(new_level = level)
      old_level = level
      self.level = new_level
      yield
    ensure
      self.level = old_level
    end

    private

    # Override this internal Logger method to clear line
    def add(*args)
      clear_line
      super(*args)
    end

    def clear_line
      return unless @progress_msg
      print_no_newline("\e[2K\r")
    end

    # Log format (from Logger implementation). Used by Logger internally
    def format_log(sev, _time, _prog, msg)
      "[#{sev.downcase}]: #{msg}\n"
    end
  end
end
