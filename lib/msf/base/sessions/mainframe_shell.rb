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

end
end
