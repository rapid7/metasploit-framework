class Pry

  # A class to manage the loading of files through the REPL loop.
  # This is an interesting trick as it processes your file as if it
  # was user input in an interactive session. As a result, all Pry
  # commands are available, and they are executed non-interactively. Furthermore
  # the session becomes interactive when the repl loop processes a
  # 'make-interactive' command in the file. The session also becomes
  # interactive when an exception is encountered, enabling you to fix
  # the error before returning to non-interactive processing with the
  # 'make-non-interactive' command.

  class REPLFileLoader
    def initialize(file_name)
      full_name = File.expand_path(file_name)
      raise RuntimeError, "No such file: #{full_name}" if !File.exist?(full_name)

      define_additional_commands
      @content = File.read(full_name)
    end

    # Switch to interactive mode, i.e take input from the user
    # and use the regular print and exception handlers.
    # @param [Pry] _pry_ the Pry instance to make interactive.
    def interactive_mode(_pry_)
      _pry_.config.input = Pry.config.input
      _pry_.config.print = Pry.config.print
      _pry_.config.exception_handler = Pry.config.exception_handler
      Pry::REPL.new(_pry_).start
    end

    # Switch to non-interactive mode. Essentially
    # this means there is no result output
    # and that the session becomes interactive when an exception is encountered.
    # @param [Pry] _pry_ the Pry instance to make non-interactive.
    def non_interactive_mode(_pry_, content)
      _pry_.print = proc {}
      _pry_.exception_handler = proc do |o, e, _p_|
        _p_.run_command "cat --ex"
        o.puts "...exception encountered, going interactive!"
        interactive_mode(_pry_)
      end

      content.lines.each do |line|
        break unless _pry_.eval line, :generated => true
      end

      unless _pry_.eval_string.empty?
        _pry_.output.puts "#{_pry_.eval_string}...exception encountered, going interactive!"
        interactive_mode(_pry_)
      end
    end

    # Define a few extra commands useful for flipping back & forth
    # between interactive/non-interactive modes
    def define_additional_commands
      s = self

      Pry::Commands.command "make-interactive", "Make the session interactive" do
        s.interactive_mode(_pry_)
      end

      Pry::Commands.command "load-file", "Load another file through the repl" do |file_name|
        s.non_interactive_mode(_pry_, File.read(File.expand_path(file_name)))
      end
    end

    # Actually load the file through the REPL by setting file content
    # as the REPL input stream.
    def load
      non_interactive_mode(Pry.new, @content)
    end
  end
end
