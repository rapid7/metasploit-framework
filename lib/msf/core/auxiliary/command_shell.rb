# -*- coding: binary -*-


module Msf

###
#
# This module provides methods for scanning modules that yield
# Command Shell sessions.
#
###

module Auxiliary::CommandShell

  include Msf::Sessions::CommandShellOptions

  #
  # Ghetto
  #
  module CRLFLineEndings
    def put(str, opts={})
      return super if not str
      super(str.strip + "\r\n", opts)
    end
    def write(str, opts={})
      return super if not str
      super(str.strip + "\r\n", opts)
    end
  end


  def start_session(obj, info, ds_merge, crlf = false, sock = nil, sess = nil)
    if crlf
      # Windows telnet server requires \r\n line endings and it doesn't
      # seem to affect anything else.
      obj.sock.extend(CRLFLineEndings)
    end

    sock ||= obj.respond_to?(:sock) ? obj.sock : nil
    sess ||= Msf::Sessions::CommandShell.new(sock)
    sess.set_from_exploit(obj)

    # Clean up the stored data
    sess.exploit_datastore.merge!(ds_merge)

    # Prevent the socket from being closed
    obj.sockets.delete(sock) if sock
    obj.sock = nil if obj.respond_to?(:sock)

    framework.sessions.register(sess)

    if sess.respond_to?(:bootstrap)
      sess.bootstrap(datastore)

      return unless sess.alive
    end
    sess.process_autoruns(datastore)
    sess.info = info unless info.blank?

    # Notify the framework that we have a new session opening up...
    # Don't let errant event handlers kill our session
    begin
      framework.events.on_session_open(sess)
    rescue ::Exception => e
      wlog("Exception in on_session_open event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    sess
  end

end
end
