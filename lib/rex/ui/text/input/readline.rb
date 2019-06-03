# -*- coding: binary -*-
require 'rex/ui'

module Rex
module Ui
module Text

begin

  ###
  #
  # This class implements standard input using readline against
  # standard input.  It supports tab completion.
  #
  ###
  class Input::Readline < Rex::Ui::Text::Input

    #
    # Initializes the readline-aware Input instance for text.
    #
    def initialize(tab_complete_proc = nil)
      if(not Object.const_defined?('Readline'))
        require 'readline'
      end

      self.extend(::Readline)

      if (tab_complete_proc)
        ::Readline.basic_word_break_characters = ""
        ::Readline.completion_proc = tab_complete_proc
        @rl_saved_proc = tab_complete_proc
      end
    end

    #
    # Reattach the original completion proc
    #
    def reset_tab_completion(tab_complete_proc = nil)
      ::Readline.basic_word_break_characters = "\x00"
      ::Readline.completion_proc = tab_complete_proc || @rl_saved_proc
    end


    #
    # Retrieve the line buffer
    #
    def line_buffer
      if defined? RbReadline
        RbReadline.rl_line_buffer
      else
        ::Readline.line_buffer
      end
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
        ::Readline::HISTORY.pop if (line and line.empty?)
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
      # rb-readlines's Readline.readline hardcodes the input and output to
      # $stdin and $stdout, which means setting `Readline.input` or
      # `Readline.ouput` has no effect when running `Readline.readline` with
      # rb-readline, so need to reimplement
      # []`Readline.readline`](https://github.com/luislavena/rb-readline/blob/ce4908dae45dbcae90a6e42e3710b8c3a1f2cd64/lib/readline.rb#L36-L58)
      # for rb-readline to support setting input and output.  Output needs to
      # be set so that colorization works for the prompt on Windows.
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

      if defined? RbReadline
        RbReadline.rl_instream = fd
        RbReadline.rl_outstream = output

        begin
          line = RbReadline.readline(reset_sequence + prompt)
        rescue ::Exception => exception
          RbReadline.rl_cleanup_after_signal()
          RbReadline.rl_deprep_terminal()

          raise exception
        end

        if add_history && line
          # Don't add duplicate lines to history
          if ::Readline::HISTORY.empty? || line != ::Readline::HISTORY[-1]
            RbReadline.add_history(line)
          end
        end

        line.try(:dup)
      else
        # The line that's read is immediately added to history
        line = ::Readline.readline(reset_sequence + prompt, true)

        # Don't add duplicate lines to history
        if ::Readline::HISTORY.length > 1 && line == ::Readline::HISTORY[-2]
          ::Readline::HISTORY.pop
        end

        line
      end
    end

  end
rescue LoadError
end

end
end
end
