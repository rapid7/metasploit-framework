# -*- coding: binary -*-

module Rex
module Ui
module Text

begin

  ###
  #
  # This class implements standard input using Reline against
  # standard input.  It supports tab completion.
  #
  ###
  class Input::Readline < Rex::Ui::Text::Input

    #
    # Initializes the readline-aware Input instance for text.
    #
    def initialize(tab_complete_proc = nil)
      self.extend(::Reline)

      if tab_complete_proc
        ::Reline.basic_word_break_characters = ""
        @rl_saved_proc = with_error_handling(tab_complete_proc)
        ::Reline.completion_proc = @rl_saved_proc
      end
    end

    #
    # Reattach the original completion proc
    #
    def reset_tab_completion(tab_complete_proc = nil)
      ::Reline.basic_word_break_characters = "\x00"
      ::Reline.completion_proc = tab_complete_proc ? with_error_handling(tab_complete_proc) : @rl_saved_proc
    end


    #
    # Retrieve the line buffer
    #
    def line_buffer
      ::Reline.line_buffer
    end

    attr_accessor :prompt

    #
    # Whether or not the input medium supports readline.
    #
    def supports_readline
      true
    end

    #
    # Calls sysread on the standard input handle.
    #
    def sysread(len = 1)
      begin
        self.fd.sysread(len)
      rescue ::Errno::EINTR
        retry
      end
    end

    #
    # Read a line from stdin
    #
    def gets()
      begin
        self.fd.gets()
      rescue ::Errno::EINTR
        retry
      end
    end

    #
    # Stick readline into a low-priority thread so that the scheduler doesn't slow
    # down other background threads. This is important when there are many active
    # background jobs, such as when the user is running Karmetasploit
    #
    def pgets

      line = nil
      orig = Thread.current.priority

      begin
        Thread.current.priority = -20

        output.prompting
        line = readline_with_output(prompt, true)
        ::Reline::HISTORY.pop if (line and line.empty?)
      ensure
        Thread.current.priority = orig || 0
      end

      line
    end

    #
    # Returns the output pipe handle
    #
    def fd
      $stdin
    end

    #
    # Indicates that this input medium as a shell builtin, no need
    # to extend.
    #
    def intrinsic_shell?
      true
    end

    #
    # The prompt that is to be displayed.
    #
    attr_accessor :prompt
    #
    # The output handle to use when displaying the prompt.
    #
    attr_accessor :output

    private

    def readline_with_output(prompt, add_history=false)
      # Output needs to be set so that colorization works for the prompt on Windows.

      self.prompt = prompt

      # TODO: there are unhandled quirks in async output buffering that
      # we have not solved yet, for instance when loading meterpreter
      # extensions, supporting Windows, printing output from commands, etc.
      # Remove this guard when issues are resolved.
=begin
      reset_sequence = "\n\001\r\033[K\002"
      if (/mingw/ =~ RUBY_PLATFORM)
        reset_sequence = ""
      end
=end
      reset_sequence = ""

      ::Reline.input = fd
      ::Reline.output = output

      line = ::Reline.readline(reset_sequence + prompt, add_history)

      # Don't add duplicate lines to history
      if ::Reline::HISTORY.length > 1 && line == ::Reline::HISTORY[-2]
        ::Reline::HISTORY.pop
      end

      line
    end

    private

    def with_error_handling(proc)
      proc do |*args|
        proc.call(*args)
      rescue StandardError => e
        elog("tab_complete_proc has failed with args #{args}", error: e)
        []
      end
    end

  end
rescue LoadError
end

end
end
end
