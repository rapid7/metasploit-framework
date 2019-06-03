# -*- coding: binary -*-
require 'rex/ui'

begin
  require 'windows_console_color_support'
rescue ::LoadError
end

module Rex
module Ui
module Text

###
#
# This class implements output against standard out.
#
###
class Output::Stdio < Rex::Ui::Text::Output
  #
  # Attributes
  #

  # @!attribute io
  #   The raw `IO` backing this Text output.  Defaults to `$stdout`
  #
  #   @return [#flush, #puts, #write]
  attr_writer :io

  #
  # Constructor
  #

  # @param options [Hash{Symbol => IO}]
  # @option options [IO]
  def initialize(options={})
    options.assert_valid_keys(:io)

    super()

    self.io = options[:io]
  end

  #
  # Methods
  #

  def flush
    io.flush
  end

  # IO to write to.
  #
  # @return [IO] Default to `$stdout`
  def io
    @io ||= $stdout
  end

  # Use ANSI Control chars to reset prompt position for async output
  # SEE https://github.com/rapid7/metasploit-framework/pull/7570
  def print_line(msg = '')
    # TODO: there are unhandled quirks in async output buffering that
    # we have not solved yet, for instance when loading meterpreter
    # extensions, supporting Windows, printing output from commands, etc.
    # Remove this guard when issues are resolved.
=begin
    if (/mingw/ =~ RUBY_PLATFORM)
      print(msg + "\n")
      return
    end
    print("\033[s") # Save cursor position
    print("\r\033[K" + msg + "\n")
    if input and input.prompt
      print("\r\033[K")
      print(input.prompt.tr("\001\002", ''))
      print(input.line_buffer.tr("\001\002", ''))
      print("\033[u\033[B") # Restore cursor, move down one line
    end
=end

    print(msg + "\n")
  end

  #
  # Prints the supplied message to standard output.
  #
  def print_raw(msg = '')
    if (Rex::Compat.is_windows and supports_color?)
      WindowsConsoleColorSupport.new(io).write(msg)
    else
      io.print(msg)
    end

    io.flush

    msg
  end
  alias_method :write, :print_raw

  def supports_color?
    case config[:color]
    when true
      return true
    when false
      return false
    else # auto
      if (Rex::Compat.is_windows)
        return true
      end
      term = Rex::Compat.getenv('TERM')
      return (term and term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i) != nil)
    end
  end
end

end
end
end

