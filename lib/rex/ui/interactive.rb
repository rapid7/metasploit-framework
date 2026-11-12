# -*- coding: binary -*-
module Rex
module Ui

###
#
# This class implements the stubs that are needed to provide an interactive
# user interface that is backed against something arbitrary.
#
###
module Interactive

  #
  # Interactive sessions by default may interact with the local user input
  # and output.
  #
  include Rex::Ui::Subscriber

  #
  # Starts interacting with the session at the most raw level, simply
  # forwarding input from user_input to rstream and forwarding input from
  # rstream to user_output.
  #
  def interact(user_input, user_output)

    # Detach from any existing console
    if self.interacting
      detach()
    end

    init_ui(user_input, user_output)

    self.interacting = true
    self.completed = false

    eof = false

    # Start the readline stdin monitor
    # XXX disabled
    # user_input.readline_start() if user_input.supports_readline

    # Handle suspend notifications
    handle_suspend

    handle_usr1

    handle_winch

    # As long as we're interacting...
    while (self.interacting == true)

      begin
        _interact

      rescue Interrupt
        # If we get an interrupt exception, ask the user if they want to
        # abort the interaction.  If they do, then we return out of
        # the interact function and call it a day.
        eof = true if (_interrupt)

      rescue EOFError, Errno::ECONNRESET, IOError
        # If we reach EOF or the connection is reset...
        eof = true

      end

      break if eof
    end

    begin

      # Restore the suspend handler
      restore_suspend

      restore_winch

      # If we've hit eof, call the interact complete handler
      _interact_complete if (eof == true)

      # Shutdown the readline thread
      # XXX disabled
      # user_input.readline_stop() if user_input.supports_readline

      # Detach from the input/output handles
      reset_ui()

    ensure
      # Mark this as completed
      self.completed = true
    end

    # if another session was requested, store it
    next_session = self.next_session
    # clear the value from the object
    self.next_session = nil

    # return this session id
    return next_session
  end

  #
  # Stops the current interaction
  #
  def detach
    if (self.interacting)
      self.interacting = false
      while(not self.completed)
        ::IO.select(nil, nil, nil, 0.25)
      end
    end
  end

  #
  # Whether or not the session is currently being interacted with
  #
  attr_accessor   :interacting

  #
  # If another session needs interaction, this is where it goes
  #
  attr_accessor   :next_session

  #
  # Whether or not the session has completed interaction
  #
  attr_accessor	:completed

  attr_accessor :on_print_proc
  attr_accessor :on_command_proc

  #
  # A function to be run when running a session command hits an error
  #
  # @return [Proc,nil] A function to be run when running a session command hits an error
  attr_accessor :on_run_command_error_proc

protected

  #
  # The original suspend proc.
  #
  attr_accessor :orig_suspend
  attr_accessor :orig_usr1
  attr_accessor :orig_winch

  #
  # Stub method that is meant to handler interaction
  #
  def _interact
  end

  #
  # Called when an interrupt is sent.
  #
  def _interrupt
    true
  end

  #
  # Called when a suspend is sent.
  #
  def _suspend
    false
  end

  #
  # Called when interaction has completed and one of the sides has closed.
  #
  def _interact_complete
    true
  end

  #
  # Read from remote and write to local.
  #
  def _stream_read_remote_write_local(stream)
    data = stream.get

    self.on_print_proc.call(data) if self.on_print_proc
    user_output.print(data)
  end

  #
  # Read from local and write to remote.
  #
  def _stream_read_local_write_remote(stream)
    data = user_input.gets

    self.on_command_proc.call(data) if self.on_command_proc
    stream.put(data)
  end

  #
  # The local file descriptor handle.
  #
  def _local_fd
    user_input.fd
  end

  #
  # The remote file descriptor handle.
  #
  def _remote_fd(stream)
    stream.fd
  end

  #
  # Interacts with two streaming connections, reading data from one and
  # writing it to the other.  Both are expected to implement Rex::IO::Stream.
  #
  def interact_stream(stream)
    while self.interacting && _remote_fd(stream)

      # Select input and rstream
      sd = Rex::ThreadSafe.select([ _local_fd, _remote_fd(stream) ], nil, nil, 0.25)

      # Cycle through the items that have data
      # From the stream?  Write to user_output.
      sd[0].each { |s|
        if (s == _remote_fd(stream))
          _stream_read_remote_write_local(stream)
        # From user_input?  Write to stream.
        elsif (s == _local_fd)
          _stream_read_local_write_remote(stream)
        end
      } if (sd)

      Thread.pass
    end
  end

  #
  # Raised in the interacting thread to abort a pending readline call, either
  # because the user pressed Ctrl+Z or because interaction was stopped from
  # another thread. Like Interrupt, these are not StandardErrors so they are
  # not swallowed by a generic rescue before reaching the interaction loop.
  #
  # rubocop:disable Lint/InheritException
  class ReadlineSuspend < ::Exception; end
  class ReadlineDetach < ::Exception; end
  # rubocop:enable Lint/InheritException

  # Terminal escape sequences: CSI (colours, cursor movement, ...), OSC
  # (window title, ...) and two character escapes
  READLINE_ESCAPE_SEQUENCE = %r{\e\[[0-9;?<=>!]*[ -/]*[@-~]|\e\][^\a\e]*(?:\a|\e\\)?|\e[@-Z\\-_]}
  # CSI sequences other than colours (SGR), such as clearing the screen
  READLINE_CONTROL_SEQUENCE = %r{\e\[[0-9;?<=>!]*[ -/]*[@-ln-~]}
  # Longest incomplete line used as the prompt. Anything longer is output
  # without a newline (or a progress bar) and is printed as it arrives.
  READLINE_PROMPT_MAX = 1024
  # Reads shorter than this mean the remote side has stopped sending for now
  READLINE_SHORT_READ = 4096

  #
  # Whether the local input is a readline input that can be used for line
  # editing while interacting with a line-oriented remote stream. Output that
  # arrives while a line is being edited is printed above it and the line is
  # redrawn, which needs rb-readline on a terminal. On Windows rb-readline
  # does not wait for input between calls to its event hook, so it is not
  # used there.
  #
  def interact_with_readline?
    defined?(Rex::Ui::Text::Input::Readline) && user_input.is_a?(Rex::Ui::Text::Input::Readline) &&
      defined?(::RbReadline) && user_input.fd.tty? && !Rex::Compat.is_windows
  end

  #
  # Interacts with a line-oriented stream through the local readline input so
  # that line editing and history work. Remote output is read on a separate
  # thread and printed as soon as it arrives; the trailing incomplete line of
  # output (usually the remote shell prompt) is used as the readline prompt.
  #
  # Output that arrives while a line is being typed is printed from
  # rb-readline's event hook, which runs in the thread reading the line
  # between key presses, so the line can be redrawn without racing readline.
  #
  # Classes using this must implement _readline_read_remote(stream) and
  # _readline_write_remote(stream, line).
  #
  def interact_readline(stream)
    input = user_input
    output = user_output
    old_prompt = input.prompt
    lock = ::Mutex.new
    interacting_thread = ::Thread.current
    finished = false

    @readline_pending = ''
    @readline_long_line = false
    @readline_waiting = false
    @readline_queue = []
    @readline_dequeued = ::ConditionVariable.new
    input.prompt = ''
    previous_tab = readline_bind_tab(:rl_tab_insert)
    previous_event_hook = ::RbReadline.rl_event_hook
    readline_event_hook(proc { lock.synchronize { readline_print_queued(input, output) } })

    begin
      # Only while reading a line, so Ctrl+Z at the question asked by _suspend
      # is ignored. The lock can't be taken in a trap handler.
      previous_tstp = ::Signal.trap('TSTP') { interacting_thread.raise(ReadlineSuspend) if @readline_waiting }
    rescue ::ArgumentError
      # No SIGTSTP on this platform
      previous_tstp = nil
    end

    reader = Rex::ThreadFactory.spawn('InteractReadlineReader', false) do
      readline_read_loop(stream, input, output, lock)
    rescue ::StandardError => e
      # The remote side went away; abort the readline call in progress so that
      # the session is closed, as it would be by the non-readline loop.
      lock.synchronize { interacting_thread.raise(::EOFError, e.message) unless finished }
    else
      # Interaction was stopped from elsewhere while waiting for a line
      lock.synchronize { interacting_thread.raise(ReadlineDetach) if @readline_waiting && !finished }
    end

    while interacting
      begin
        lock.synchronize { @readline_waiting = true }
        line = input.pgets
        lock.synchronize do
          # The prompt stays on screen with the entered line. Output that
          # arrived just before Enter is printed below them.
          @readline_pending = ''
          @readline_long_line = false
          input.prompt = ''
          readline_stop_waiting(input, output)
        end
        # Ctrl+D sends an empty line, like the non-readline loop does
        _readline_write_remote(stream, line.to_s.chomp)
      rescue ReadlineSuspend
        lock.synchronize do
          readline_stop_interrupted(input, output)
          _suspend
        end
      rescue ReadlineDetach
        break
      end
    end
  ensure
    # Anything the reader raises from here on is delivered after cleanup
    ::Thread.handle_interrupt(::Object => :never) do
      lock&.synchronize { finished = true }
      reader&.kill
      @readline_waiting = false
      readline_event_hook(nil, previous_event_hook)
      readline_bind_tab(previous_tab) if previous_tab
      ::Signal.trap('TSTP', previous_tstp) if previous_tstp
      # Output can still be queued if reading the line was interrupted, e.g.
      # by Ctrl+C
      lock&.synchronize { readline_stop_interrupted(input, output) }
      input.prompt = old_prompt if input
    end
  end

  #
  # Reads remote output until interaction stops. While a line is being typed
  # the output is queued for readline's event hook, otherwise it is printed
  # straight away.
  #
  # A short read may be the last output before the remote side closes, and
  # the read that finds it closed also closes the session (see shell_read).
  # So after a short read the hook prints the queued output before reading
  # goes on, or it would be printed after the session was reported closed.
  # After a longer read more output is likely on its way.
  #
  def readline_read_loop(stream, input, output, lock)
    while interacting
      fd = _remote_fd(stream)
      raise ::EOFError, 'The remote stream was closed' unless fd

      next unless Rex::ThreadSafe.select([fd], nil, nil, 0.25)

      data = _readline_read_remote(stream)
      next if data.nil? || data.empty?

      lock.synchronize do
        if @readline_waiting
          @readline_queue << data
          if data.bytesize < READLINE_SHORT_READ
            @readline_dequeued.wait(lock, 0.25) while interacting && !@readline_queue.empty?
          end
        else
          readline_print_remote(data, input, output, false)
        end
      end
    end
  end

  #
  # Called from readline's event hook: prints queued output and redraws the
  # line being edited. Waits while readline is in the middle of something
  # else, e.g. a history search, which has its own prompt.
  #
  def readline_print_queued(input, output)
    return if @readline_queue.empty? || !::RbReadline.rl_isstate(::RbReadline::RL_STATE_READCMD)

    readline_print_remote(readline_dequeue, input, output, true)
  end

  #
  # Prints anything still queued once readline has stopped reading a line.
  #
  def readline_stop_waiting(input, output)
    @readline_waiting = false
    data = readline_dequeue
    readline_print_remote(data, input, output, false) unless data.empty?
  end

  #
  # Prints anything still queued when reading a line was interrupted, e.g. by
  # Ctrl+Z or Ctrl+C, in place of the prompt and the line being edited.
  #
  def readline_stop_interrupted(input, output)
    readline_clear_display(output) unless @readline_queue.empty? || @readline_long_line
    readline_stop_waiting(input, output)
  end

  #
  # Takes the output queued while a line was being edited and lets the reader
  # read more.
  #
  def readline_dequeue
    data = @readline_queue.join
    @readline_queue.clear
    @readline_dequeued.broadcast
    data
  end

  #
  # Prints complete lines of remote output and turns the trailing partial
  # line into the readline prompt. With redraw, the prompt and line being
  # edited are on screen and are drawn again below the output.
  #
  def readline_print_remote(data, input, output, redraw)
    lines = (@readline_pending + data).split("\n", -1)
    @readline_pending = lines.pop.to_s

    # Terminal control sequences other than colours (clearing the screen,
    # moving the cursor) are printed now instead of becoming part of the
    # prompt, where they would be replayed every time the line is redrawn.
    control_end = 0
    @readline_pending.scan(READLINE_CONTROL_SEQUENCE) { control_end = ::Regexp.last_match.end(0) }
    control = @readline_pending[0, control_end]
    @readline_pending = @readline_pending[control_end..]

    # While a long line is being printed the cursor is at the end of it and
    # the line being edited is not on screen, so there is nothing to wipe
    readline_clear_display(output) if redraw && !@readline_long_line

    unless lines.empty?
      output.print(lines.join("\n") + "\n")
      @readline_long_line = false
    end
    output.print(control) unless control.empty?

    if @readline_long_line || @readline_pending.bytesize > READLINE_PROMPT_MAX
      # Too long to be a prompt. Print it as it arrives, without adding a line
      # break, and draw the line being edited again once the line ends.
      output.print(@readline_pending)
      @readline_pending = ''
      input.prompt = ''
      if redraw && !@readline_long_line
        # Until then, anything typed is echoed after the output like in a
        # terminal. This also brings readline's idea of the screen up to date.
        ::RbReadline.rl_set_prompt('')
        ::RbReadline.rl_forced_update_display
      end
      @readline_long_line = true
      return
    end

    input.prompt = readline_prompt(@readline_pending)

    if redraw
      ::RbReadline.rl_set_prompt(input.prompt)
      ::RbReadline.rl_forced_update_display
    end
  end

  # Name of the RbReadline method that is set as rl_event_hook, which
  # rb-readline calls by name while waiting for a key
  READLINE_EVENT_HOOK = :rex_ui_interactive_event_hook

  #
  # Sets the callback run by rb-readline while waiting for a key, or removes
  # it and restores the previous hook.
  #
  def readline_event_hook(callback, previous = nil)
    unless ::RbReadline.respond_to?(READLINE_EVENT_HOOK)
      ::RbReadline.define_singleton_method(READLINE_EVENT_HOOK) do
        ::Thread.current[READLINE_EVENT_HOOK]&.call
      end
    end

    ::Thread.current[READLINE_EVENT_HOOK] = callback
    ::RbReadline.rl_event_hook = callback ? READLINE_EVENT_HOOK : previous
  end

  READLINE_TAB = "\t"

  #
  # Binds Tab to an rb-readline function and returns the previous one. While
  # interacting, Tab inserts a tab that is sent to the remote side, the same
  # as without readline, instead of completing console commands.
  #
  def readline_bind_tab(function)
    return unless defined?(::RbReadline)

    previous = ::RbReadline.rl_function_of_keyseq(READLINE_TAB, nil, nil)
    ::RbReadline.rl_bind_key(READLINE_TAB, function)
    previous
  end

  #
  # Wipes the prompt and the line being edited, including the rows above the
  # cursor when they are wider than the terminal.
  #
  def readline_clear_display(output)
    ::RbReadline._rl_move_vert(0)
    output.print("\r\e[J")
  end

  #
  # Turns remote text into a prompt readline can display. Terminal escape
  # sequences (colours, window titles) are marked as non-printing, otherwise
  # readline counts them as visible characters and wraps the line wrongly.
  #
  def readline_prompt(text)
    text = text.split("\r").last.to_s
    text.gsub(READLINE_ESCAPE_SEQUENCE) { |seq| "\x01#{seq}\x02" }
  end


  #
  # Installs a signal handler to monitor suspend signal notifications.
  #
  def handle_suspend
    if orig_suspend.nil?
      begin
        self.orig_suspend = Signal.trap("TSTP") do
          Thread.new { _suspend }.join
        end
      rescue
      end
    end
  end


  #
  # Restores the previously installed signal handler for suspend
  # notifications.
  #
  def restore_suspend
    begin
      if orig_suspend
        Signal.trap("TSTP", orig_suspend)
      else
        Signal.trap("TSTP", "DEFAULT")
      end
      self.orig_suspend = nil
    rescue
    end
  end

  def handle_usr1
    if orig_usr1.nil?
      begin
        self.orig_usr1 = Signal.trap("USR1") do
          Thread.new { _usr1 }.join
        end
      rescue
      end
    end
  end

  def handle_winch
    if orig_winch.nil?
      begin
        self.orig_winch = Signal.trap("WINCH") do
          Thread.new { _winch }.join
        end
      rescue
      end
    end
  end

  def restore_winch
    begin
      if orig_winch
        Signal.trap("WINCH", orig_winch)
      else
        Signal.trap("WINCH", "DEFAULT")
      end
      self.orig_winch = nil
    rescue
    end
  end

  def _winch
  end

  def restore_usr1
    begin
      if orig_usr1
        Signal.trap("USR1", orig_usr1)
      else
        Signal.trap("USR1", "DEFAULT")
      end
      self.orig_usr1 = nil
    rescue
    end
  end

  #
  # Prompt the user for input if possible.
  # XXX: This is not thread-safe on Windows
  #
  def prompt(query)
    if (user_output and user_input)
      user_output.print("\n" + query)
      user_input.sysread(2)
    end
  end

  #
  # Check the return value of a yes/no prompt
  #
  def prompt_yesno(query)
    (prompt(query + " [y/N]  ") =~ /^y/i) ? true : false
  end

end

end
end

