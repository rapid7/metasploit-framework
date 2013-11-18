#
# $Id$
# $Revision$
#

module Msf

###
#
# This class hooks all sockets created by a running exploit
#
###

class Plugin::SocketLogger < Msf::Plugin

  ###
  #
  # This class implements a socket communication logger
  #
  ###
  class MySocketEventHandler
    include Rex::Socket::Comm::Events

    def initialize(path, prefix)
      @path   = path
      @prefix = prefix
    end

    def on_before_socket_create(comm, param)
    end

    def on_socket_created(comm, sock, param)
      # Sockets created by the exploit have MsfExploit set and MsfPayload not set
      if (param.context['MsfExploit'] and (! param.context['MsfPayload'] ))
        sock.extend(SocketLogger::SocketTracer)
        sock.context = param.context
        sock.params = param
        sock.initlog(@path, @prefix)

      end
    end
  end


  def initialize(framework, opts)
    log_path    = opts['path'] || "/tmp"
    log_prefix  = opts['prefix'] || "socket_"

    super
    @eh = MySocketEventHandler.new(log_path, log_prefix)
    Rex::Socket::Comm::Local.register_event_handler(@eh)
  end

  def cleanup
    Rex::Socket::Comm::Local.deregister_event_handler(@eh)
  end

  def name
    "socket_logger"
  end

  def desc
    "Logs all socket operations to hex dumps in /tmp"
  end

protected
end

end

# This module extends the captured socket instance
module SocketLogger
module SocketTracer

  @@last_id = 0

  attr_accessor :context, :params

  # Hook the write method
  def write(buf, opts = {})
    @fd.puts "WRITE (#{buf.length} bytes)"
    @fd.puts Rex::Text.to_hex_dump(buf)
    super(buf, opts)
  end

  # Hook the read method
  def read(length = nil, opts = {})
    r = super(length, opts)

    @fd.puts "READ (#{r.length} bytes)"
    @fd.puts Rex::Text.to_hex_dump(r)
    return r
  end

  def close(*args)
    super(*args)
    @fd.close
  end

  def initlog(path, prefix)
    @log_path    = path
    @log_prefix  = prefix
    @log_id      = @@last_id
    @@last_id   += 1
    @fd = File.open(File.join(@log_path, "#{@log_prefix}#{@log_id}.log"), "w")
    @fd.puts "Socket created at #{Time.now}"
    @fd.puts "Info: #{params.proto} #{params.localhost}:#{params.localport} -> #{params.peerhost}:#{params.peerport}"
    @fd.puts ""
  end

end
end
