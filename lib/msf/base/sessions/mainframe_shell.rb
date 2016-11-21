# -*- coding: binary -*-

require 'msf/base/sessions/command_shell'

module Msf::Sessions

###
#
# This class provides basic interaction with a Unix Systems Service
# command shell on a mainframe (IBM System Z) running Z/OS
# This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
#  Date:    Oct 8, 2015
#  Author:  Bigendian Smalls
#
###
class MainframeShell < Msf::Sessions::CommandShell

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # This interface supports interacting with a single command shell.
  #
  include Msf::Session::Provider::SingleCommandShell

  ##
  #
  # initialize as mf shell session
  #
  def initialize(*args)
    self.platform = 'mainframe'
    self.arch = ARCH_ZARCH
    self.translate_1047 = true
    super
  end

  ##
  #
  # Returns the session description.
  #
  def desc
    "Mainframe shell"
  end

  ##
  #
  # override shell_read to include decode of cp1047
  #
  def shell_read(length=-1, timeout=1)
    #mfimpl
    if self.respond_to?(:ring)
      return Rex::Text.from_ibm1047(shell_read_ring(length,timeout))
    end

    begin
      rv = Rex::Text.from_ibm1047(rstream.get_once(length, timeout))
      framework.events.on_session_output(self, rv) if rv
      return rv
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      shell_close
      raise e
    end
  end

  ##
  #
  # override shell_write to include encode of cp1047
  #
  def shell_write(buf)
    #mfimpl
    return unless buf

    begin
      framework.events.on_session_command(self, buf.strip)
      rstream.write(Rex::Text.to_ibm1047(buf))
    rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      shell_close
      raise e
    end
  end

  def execute_file(full_path, args)
    #mfimpl
    raise NotImplementedError
  end

  # need to do more testing on this before we either use the default in command_shell
  # or write a new one.  For now we just make it unavailble. This prevents a hang on
  # initial session creation.  See PR#6067
  undef_method  :process_autoruns

  def desc
    "Mainframe USS session"
  end

  attr_accessor :translate_1047   # tells the session whether or not to translate
                                  # ebcdic (cp1047) <-> ASCII for certain mainframe payloads
                                  # this will be used in post modules to be able to switch on/off the
                                  # translation on file transfers, for instance

  protected

  ##
  #
  # _interact_ring overridden to include decoding of cp1047 data
  #
  def _interact_ring
    begin
      rdr = framework.threads.spawn("RingMonitor", false) do
        seq = nil

        while self.interacting
          # Look for any pending data from the remote ring
          nseq,data = ring.read_data(seq)

          # Update the sequence number if necessary
          seq = nseq || seq

          # Write output to the local stream if successful
          user_output.print(Rex::Text.from_ibm1047(data)) if data

          begin
            # Wait for new data to arrive on this session
            ring.wait(seq)
          rescue EOFError => e
            print_error("EOFError: #{e.class}: #{e}")
            break
          end
        end
      end

      while self.interacting
        # Look for any pending input or errors from the local stream
        sd = Rex::ThreadSafe.select([ _local_fd ], nil, [_local_fd], 5.0)

        # Write input to the ring's input mechanism
        shell_write(user_input.gets) if sd
      end
    ensure
      rdr.kill
    end
  end

end
end
