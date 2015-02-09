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
      if param.context and param.context['MsfExploit'] and (! param.context['MsfPayload'])
        sock.extend(SocketLogger::SocketTracer)
        sock.context = param.context
        sock.params = param
        sock.initlog(@path, @prefix)
      end
    end
  end


  def initialize(framework, opts)
    log_path    = opts['path'] || Msf::Config.log_directory
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
    "Log socket operations to a directory as individual files"
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
    @fd.puts "WRITE\t#{buf.length}\t#{Rex::Text.encode_base64(buf)}"
    @fd.flush
    super(buf, opts)
  end

  # Hook the read method
  def read(length = nil, opts = {})
    r = super(length, opts)
    @fd.puts "READ\t#{ r ? r.length : 0}\t#{Rex::Text.encode_base64(r.to_s)}"
    @fd.flush
    return r
  end

  def close(*args)
    super(*args)
    @fd.close
  end

  def format_socket_conn
    "#{params.proto.upcase} #{params.localhost}:#{params.localport} > #{params.peerhost}:#{params.peerport}"
  end

  def format_module_info
    return "" unless params.context and params.context['MsfExploit']
    if params.context['MsfExploit'].respond_to? :fullname
      return "via " + params.context['MsfExploit'].fullname
    end
    "via " + params.context['MsfExploit'].to_s
  end

  def initlog(path, prefix)
    @log_path    = path
    @log_prefix  = prefix
    @log_id      = @@last_id
    @@last_id   += 1
    @fd = File.open(File.join(@log_path, "#{@log_prefix}#{@log_id}.log"), "w")
    @fd.puts "Socket created at #{Time.now} (#{Time.now.to_i})"
    @fd.puts "Info: #{format_socket_conn} #{format_module_info}"
    @fd.puts ""
    @fd.flush
  end

end
end
