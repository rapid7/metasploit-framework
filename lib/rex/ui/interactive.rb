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
    if(self.interacting)
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

    # Return whether or not EOF was reached
    return eof
  end

  #
  # Stops the current interaction
  #
  def detach
    if (self.interacting)
      self.interacting = false
      while(not self.completed)
        Rex.sleep(0.25)
      end
    end
  end

  #
  # Whether or not the session is currently being interacted with
  #
  attr_accessor   :interacting

  #
  # Whether or not the session has completed interaction
  #
  attr_accessor	:completed

  attr_accessor :on_print_proc
  attr_accessor :on_command_proc

protected

  #
  # The original suspend proc.
  #
  attr_accessor :orig_suspend

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
    while self.interacting

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
  # Interacts between a local stream and a remote ring buffer. This has to use
  # a secondary thread to prevent the select on the local stream from blocking
  #
  def interact_ring(ring)
    begin

    rdr = Rex::ThreadFactory.spawn("RingMonitor", false) do
      seq = nil
      while self.interacting

        # Look for any pending data from the remote ring
        nseq,data = ring.read_data(seq)

        # Update the sequence number if necessary
        seq = nseq || seq

        # Write output to the local stream if successful
        user_output.print(data) if data

        # Wait for new data to arrive on this session
        ring.wait(seq)
      end
    end

    while self.interacting

      # Look for any pending input from the local stream
      sd = Rex::ThreadSafe.select([ _local_fd ], nil, [_local_fd], 5.0)

      # Write input to the ring's input mechanism
      if sd
        data = user_input.gets
        ring.put(data)
      end
    end

    ensure
      rdr.kill
    end
  end


  #
  # Installs a signal handler to monitor suspend signal notifications.
  #
  def handle_suspend
    if (orig_suspend == nil)
      begin
        self.orig_suspend = Signal.trap("TSTP") {
          _suspend
        }
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
      if (orig_suspend)
        Signal.trap("TSTP", orig_suspend)
      else
        Signal.trap("TSTP", "DEFAULT")
      end
      self.orig_suspend = nil
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

