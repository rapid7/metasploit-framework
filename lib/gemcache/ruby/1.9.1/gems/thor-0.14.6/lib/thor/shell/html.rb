require 'thor/shell/basic'

class Thor
  module Shell
    # Inherit from Thor::Shell::Basic and add set_color behavior. Check
    # Thor::Shell::Basic to see all available methods.
    #
    class HTML < Basic
      # The start of an HTML bold sequence.
      BOLD       = "<strong>"
      # The end of an HTML bold sequence.
      END_BOLD   = "</strong>"

      # Embed in a String to clear previous color selection.
      CLEAR      = "</span>"

      # Set the terminal's foreground HTML color to black.
      BLACK      = '<span style="color: black;">'
      # Set the terminal's foreground HTML color to red.
      RED        = '<span style="color: red;">'
      # Set the terminal's foreground HTML color to green.
      GREEN      = '<span style="color: green;">'
      # Set the terminal's foreground HTML color to yellow.
      YELLOW     = '<span style="color: yellow;">'
      # Set the terminal's foreground HTML color to blue.
      BLUE       = '<span style="color: blue;">'
      # Set the terminal's foreground HTML color to magenta.
      MAGENTA    = '<span style="color: magenta;">'
      # Set the terminal's foreground HTML color to cyan.
      CYAN       = '<span style="color: cyan;">'
      # Set the terminal's foreground HTML color to white.
      WHITE      = '<span style="color: white;">'

      # Set the terminal's background HTML color to black.
      ON_BLACK   = '<span style="background-color: black">'
      # Set the terminal's background HTML color to red.
      ON_RED     = '<span style="background-color: red">'
      # Set the terminal's background HTML color to green.
      ON_GREEN   = '<span style="background-color: green">'
      # Set the terminal's background HTML color to yellow.
      ON_YELLOW  = '<span style="background-color: yellow">'
      # Set the terminal's background HTML color to blue.
      ON_BLUE    = '<span style="background-color: blue">'
      # Set the terminal's background HTML color to magenta.
      ON_MAGENTA = '<span style="background-color: magenta">'
      # Set the terminal's background HTML color to cyan.
      ON_CYAN    = '<span style="background-color: cyan">'
      # Set the terminal's background HTML color to white.
      ON_WHITE   = '<span style="background-color: white">'

      # Set color by using a string or one of the defined constants. If a third
      # option is set to true, it also adds bold to the string. This is based
      # on Highline implementation and it automatically appends CLEAR to the end
      # of the returned String.
      #
      def set_color(string, color, bold=false)
        color = self.class.const_get(color.to_s.upcase) if color.is_a?(Symbol)
        bold, end_bold = bold ? [BOLD, END_BOLD] : ['', '']
        "#{bold}#{color}#{string}#{CLEAR}#{end_bold}"
      end

      # Ask something to the user and receives a response.
      #
      # ==== Example
      # ask("What is your name?")
      #
      # TODO: Implement #ask for Thor::Shell::HTML
      def ask(statement, color=nil)
        raise NotImplementedError, "Implement #ask for Thor::Shell::HTML"
      end

      protected

        # Overwrite show_diff to show diff with colors if Diff::LCS is
        # available.
        #
        def show_diff(destination, content) #:nodoc:
          if diff_lcs_loaded? && ENV['THOR_DIFF'].nil? && ENV['RAILS_DIFF'].nil?
            actual  = File.binread(destination).to_s.split("\n")
            content = content.to_s.split("\n")

            Diff::LCS.sdiff(actual, content).each do |diff|
              output_diff_line(diff)
            end
          else
            super
          end
        end

        def output_diff_line(diff) #:nodoc:
          case diff.action
            when '-'
              say "- #{diff.old_element.chomp}", :red, true
            when '+'
              say "+ #{diff.new_element.chomp}", :green, true
            when '!'
              say "- #{diff.old_element.chomp}", :red, true
              say "+ #{diff.new_element.chomp}", :green, true
            else
              say "  #{diff.old_element.chomp}", nil, true
          end
        end

        # Check if Diff::LCS is loaded. If it is, use it to create pretty output
        # for diff.
        #
        def diff_lcs_loaded? #:nodoc:
          return true  if defined?(Diff::LCS)
          return @diff_lcs_loaded unless @diff_lcs_loaded.nil?

          @diff_lcs_loaded = begin
            require 'diff/lcs'
            true
          rescue LoadError
            false
          end
        end

    end
  end
end
