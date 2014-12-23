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

  def puts(*args)
    args.each do |argument|
      line = argument.to_s
      write(line)

      unless line.ends_with? "\n"
        # yes, this is output, but `IO#puts` uses `rb_default_rs`, which is
        # [`$/`](https://github.com/ruby/ruby/blob/3af8e150aded9d162bfd41426aaaae0279e5a653/io.c#L12168-L12172),
        # which is [`$INPUT_RECORD_SEPARATOR`](https://github.com/ruby/ruby/blob/3af8e150aded9d162bfd41426aaaae0279e5a653/lib/English.rb#L83)
        write($INPUT_RECORD_SEPARATOR)
      end
    end

    nil
  end

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

