# coding: utf-8
class Pry::Terminal
  class << self
    # Return a pair of [rows, columns] which gives the size of the window.
    #
    # If the window size cannot be determined, return nil.
    def screen_size
      rows, cols = actual_screen_size
      if rows.to_i != 0 && cols.to_i != 0
        [rows.to_i, cols.to_i]
      else
        nil
      end
    end

    # Return a screen size or a default if that fails.
    def size! default = [27, 80]
      screen_size || default
    end

    # Return a screen width or the default if that fails.
    def width!
      size![1]
    end

    # Return a screen height or the default if that fails.
    def height!
      size![0]
    end

    def actual_screen_size
      # The best way, if possible (requires non-jruby ≥1.9 or io-console gem)
      screen_size_according_to_io_console or
        # Fall back to the old standby, though it might be stale:
        screen_size_according_to_env or
        # Fall further back, though this one is also out of date without something
        # calling Readline.set_screen_size
        screen_size_according_to_readline or
        # Windows users can otherwise run ansicon and get a decent answer:
        screen_size_according_to_ansicon_env
    end

    def screen_size_according_to_io_console
      return if Pry::Helpers::BaseHelpers.jruby?

      begin
        require 'io/console'

        begin
          if $stdout.respond_to?(:tty?) && $stdout.tty? && $stdout.respond_to?(:winsize)
            $stdout.winsize
          end
        rescue Errno::EOPNOTSUPP
          # $stdout is probably a socket, which doesn't support #winsize.
        end
      rescue LoadError
        # They probably don't have the io/console stdlib or the io-console gem.
        # We'll keep trying.
      end
    end

    def screen_size_according_to_env
      size = [ENV['LINES'] || ENV['ROWS'], ENV['COLUMNS']]
      size if nonzero_column?(size)
    end

    def screen_size_according_to_readline
      if defined?(Readline) && Readline.respond_to?(:get_screen_size)
        size = Readline.get_screen_size
        size if nonzero_column?(size)
      end
    rescue Java::JavaLang::NullPointerException
      # This rescue won't happen on jrubies later than:
      #     https://github.com/jruby/jruby/pull/436
      nil
    end

    def screen_size_according_to_ansicon_env
      return unless ENV['ANSICON'] =~ /\((.*)x(.*)\)/
      size = [$2, $1]
      size if nonzero_column?(size)
    end

    private

    def nonzero_column?(size)
      size[1].to_i > 0
    end
  end
end
