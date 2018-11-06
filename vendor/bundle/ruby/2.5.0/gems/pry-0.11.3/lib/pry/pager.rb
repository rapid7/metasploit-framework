require 'pry/terminal'

# A pager is an `IO`-like object that accepts text and either prints it
# immediately, prints it one page at a time, or streams it to an external
# program to print one page at a time.
class Pry::Pager
  class StopPaging < StandardError
  end

  attr_reader :_pry_

  def initialize(_pry_)
    @_pry_ = _pry_
  end

  # Send the given text through the best available pager (if `Pry.config.pager` is
  # enabled). If you want to send text through in chunks as you generate it, use `open`
  # to get a writable object instead.
  #
  # @param [String] text
  #   Text to run through a pager.
  #
  def page(text)
    open do |pager|
      pager << text
    end
  end

  # Yields a pager object (`NullPager`, `SimplePager`, or `SystemPager`).  All
  # pagers accept output with `#puts`, `#print`, `#write`, and `#<<`.
  def open
    pager = best_available
    yield pager
  rescue StopPaging
  ensure
    pager.close if pager
  end

  private

  def enabled?; !!@enabled; end

  def output; @output; end

  # Return an instance of the "best" available pager class -- `SystemPager` if
  # possible, `SimplePager` if `SystemPager` isn't available, and `NullPager`
  # if the user has disabled paging. All pagers accept output with `#puts`,
  # `#print`, `#write`, and `#<<`. You must call `#close` when you're done
  # writing output to a pager, and you must rescue `Pry::Pager::StopPaging`.
  # These requirements can be avoided by using `.open` instead.
  def best_available
    if !_pry_.config.pager
      NullPager.new(_pry_.output)
    elsif !SystemPager.available? || Pry::Helpers::BaseHelpers.jruby?
      SimplePager.new(_pry_.output)
    else
      SystemPager.new(_pry_.output)
    end
  end

  # `NullPager` is a "pager" that actually just prints all output as it comes
  # in. Used when `Pry.config.pager` is false.
  class NullPager
    def initialize(out)
      @out = out
    end

    def puts(str)
      print "#{str.chomp}\n"
    end

    def print(str)
      write str
    end
    alias << print

    def write(str)
      @out.write str
    end

    def close
    end

    private

    def height
      @height ||= Pry::Terminal.height!
    end

    def width
      @width ||= Pry::Terminal.width!
    end
  end

  # `SimplePager` is a straightforward pure-Ruby pager. We use it on JRuby and
  # when we can't find a usable external pager.
  class SimplePager < NullPager
    def initialize(*)
      super
      @tracker = PageTracker.new(height - 3, width)
    end

    def write(str)
      str.lines.each do |line|
        @out.print line
        @tracker.record line

        if @tracker.page?
          @out.print "\n"
          @out.print "\e[0m"
          @out.print "<page break> --- Press enter to continue " \
                     "( q<enter> to break ) --- <page break>\n"
          raise StopPaging if Readline.readline("").chomp == "q"
          @tracker.reset
        end
      end
    end
  end

  # `SystemPager` buffers output until we're pretty sure it's at least a page
  # long, then invokes an external pager and starts streaming output to it. If
  # `#close` is called before then, it just prints out the buffered content.
  class SystemPager < NullPager
    def self.default_pager
      pager = ENV["PAGER"] || ""

      # Default to less, and make sure less is being passed the correct options
      if pager.strip.empty? or pager =~ /^less\b/
        pager = "less -R -F -X"
      end

      pager
    end

    @system_pager = nil

    def self.available?
      if @system_pager.nil?
        @system_pager = begin
          pager_executable = default_pager.split(' ').first
          if Pry::Helpers::BaseHelpers.windows? || Pry::Helpers::BaseHelpers.windows_ansi?
            `where #{pager_executable}`
          else
            `which #{pager_executable}`
          end
          $?.success?
        rescue
          false
        end
      else
        @system_pager
      end
    end

    def initialize(*)
      super
      @tracker = PageTracker.new(height, width)
      @buffer  = ""
      @pager   = nil
    end

    def write(str)
      if invoked_pager?
        write_to_pager str
      else
        @tracker.record str
        @buffer << str

        if @tracker.page?
          write_to_pager @buffer
        end
      end
    rescue Errno::EPIPE
      raise StopPaging
    end

    def close
      if invoked_pager?
        pager.close
      else
        @out.puts @buffer
      end
    end

    private

    def write_to_pager(text)
      pager.write @out.decolorize_maybe(text)
    end

    def invoked_pager?
      @pager
    end

    def pager
      @pager ||= IO.popen(self.class.default_pager, 'w')
    end
  end

  # `PageTracker` tracks output to determine whether it's likely to take up a
  # whole page. This doesn't need to be super precise, but we can use it for
  # `SimplePager` and to avoid invoking the system pager unnecessarily.
  #
  # One simplifying assumption is that we don't need `#page?` to return `true`
  # on the basis of an incomplete line. Long lines should be counted as
  # multiple lines, but we don't have to transition from `false` to `true`
  # until we see a newline.
  class PageTracker
    def initialize(rows, cols)
      @rows, @cols = rows, cols
      reset
    end

    def record(str)
      str.lines.each do |line|
        if line.end_with? "\n"
          @row += ((@col + line_length(line) - 1) / @cols) + 1
          @col  = 0
        else
          @col += line_length(line)
        end
      end
    end

    def page?
      @row >= @rows
    end

    def reset
      @row = 0
      @col = 0
    end

    private

    # Approximation of the printable length of a given line, without the
    # newline and without ANSI color codes.
    def line_length(line)
      line.chomp.gsub(/\e\[[\d;]*m/, '').length
    end
  end
end
