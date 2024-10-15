# -*- coding: binary -*-

module Rex
module Ui
module Text

  #
  # This class implements standard input using readline against
  # standard input.  It supports tab completion.
  #
  class Input::Readline < Rex::Ui::Text::Input

    #
    # The prompt that is to be displayed.
    #
    attr_accessor :prompt

    #
    # The output handle to use when displaying the prompt.
    #
    attr_accessor :output

    #
    # Initializes the readline-aware Input instance for text.
    #
    def initialize(tab_complete_proc = nil)
      super()
      if tab_complete_proc
        Msf::Ui::Console::MsfReadline.instance.basic_word_break_characters = ''
        # Cache the value so that we can use it when resetting the proc.
        @completion_proc = tab_complete_proc
        Msf::Ui::Console::MsfReadline.instance.completion_proc = with_error_handling(@completion_proc)
      end
    end

    #
    # Reattach the original completion proc
    #
    def reset_tab_completion(tab_complete_proc = nil)
      Msf::Ui::Console::MsfReadline.instance.basic_word_break_characters = "\x00"
      @completion_proc = with_error_handling(tab_complete_proc) if tab_complete_proc
      Msf::Ui::Console::MsfReadline.instance.completion_proc = @completion_proc
    end

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

        output.prompting(true)
        line = Msf::Ui::Console::MsfReadline.instance.readline(prompt, true, opts: { fd: fd, output: output })
      ensure
        Thread.current.priority = orig || 0
        output.prompting(false)
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

    private

    attr_accessor :completion_proc

    def with_error_handling(proc)
      proc do |*args|
        proc.call(*args)
      rescue ::StandardError => e
        elog("tab_complete_proc has failed with args #{args}", error: e)
        []
      end
    end

  end
end

end
end
