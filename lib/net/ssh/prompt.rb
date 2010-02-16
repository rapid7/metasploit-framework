module Net; module SSH

  # A basic prompt module that can be mixed into other objects. If HighLine is
  # installed, it will be used to display prompts and read input from the
  # user. Otherwise, the termios library will be used. If neither HighLine
  # nor termios is installed, a simple prompt that echos text in the clear
  # will be used.

  module PromptMethods

    # Defines the prompt method to use if the Highline library is installed.
    module Highline
      # Uses Highline#ask to present a prompt and accept input. If +echo+ is
      # +false+, the characters entered by the user will not be echoed to the
      # screen.
      def prompt(prompt, echo=true)
        @highline ||= ::HighLine.new
        @highline.ask(prompt + " ") { |q| q.echo = echo }
      end
    end

    # Defines the prompt method to use if the Termios library is installed.
    module Termios
      # Displays the prompt to $stdout. If +echo+ is false, the Termios
      # library will be used to disable keystroke echoing for the duration of
      # this method.
      def prompt(prompt, echo=true)
        $stdout.print(prompt)
        $stdout.flush

        set_echo(false) unless echo
        $stdin.gets.chomp
      ensure
        if !echo
          set_echo(true)
          $stdout.puts
        end
      end

      private

        # Enables or disables keystroke echoing using the Termios library.
        def set_echo(enable)
          term = ::Termios.getattr($stdin)

          if enable
            term.c_lflag |= (::Termios::ECHO | ::Termios::ICANON)
          else
            term.c_lflag &= ~::Termios::ECHO
          end

          ::Termios.setattr($stdin, ::Termios::TCSANOW, term)
        end
    end

    # Defines the prompt method to use when neither Highline nor Termios are
    # installed.
    module Clear
      # Displays the prompt to $stdout and pulls the response from $stdin.
      # Text is always echoed in the clear, regardless of the +echo+ setting.
      # The first time a prompt is given and +echo+ is false, a warning will
      # be written to $stderr recommending that either Highline or Termios
      # be installed.
      def prompt(prompt, echo=true)
        @seen_warning ||= false
        if !echo && !@seen_warning
          $stderr.puts "Text will be echoed in the clear. Please install the HighLine or Termios libraries to suppress echoed text."
          @seen_warning = true
        end

        $stdout.print(prompt)
        $stdout.flush
        $stdin.gets.chomp
      end
    end
  end

  # Try to load Highline and Termios in turn, selecting the corresponding
  # PromptMethods module to use. If neither are available, choose PromptMethods::Clear.
  Prompt = begin
      require 'highline'
      HighLine.track_eof = false
      PromptMethods::Highline
    rescue LoadError
      begin
        require 'termios'
        PromptMethods::Termios
      rescue LoadError
        PromptMethods::Clear
      end
    end

end; end