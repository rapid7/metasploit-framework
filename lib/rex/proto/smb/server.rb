# -*- coding: binary -*-
require 'forwardable'
require 'rex/socket'


module Rex
module Proto
module SMB

###
#
# Acts as an HTTP server, processing requests and dispatching them to
# registered procs.  Some of this server was modeled after webrick.
#
###
class Server

  include Proto
  extend Forwardable

  def_delegators :@rubysmb_server, :dialects, :guid, :shares, :add_share, :remove_share

  def initialize(port = 445, listen_host = '0.0.0.0', context = {}, comm = nil, gss_provider: nil, logger: nil)
    self.listen_host     = listen_host
    self.listen_port     = port
    self.context         = context
    self.comm            = comm
    @gss_provider        = gss_provider
    @logger              = logger
    self.listener        = nil
    @listener_thread     = nil
    @rubysmb_server      = nil
  end

  # More readable inspect that only shows the url and resources
  # @return [String]
  def inspect
    resources_str = resources.keys.map{|r| r.inspect }.join ", "

    "#<#{self.class} smb://#{listen_host}:#{listen_port} >"
  end

  #
  # Returns the hardcore alias for the HTTP service
  #
  def self.hardcore_alias(*args, **kwargs)
    gss_alias = ''
    if (gss_provider = kwargs[:gss_provider])
      gss_alias << "#{gss_provider.class}(allow_anonymous=#{gss_provider.allow_anonymous}, allow_guests=#{gss_provider.allow_guests}"
      gss_alias << ", default_domain=#{gss_provider.default_domain}" if gss_provider.respond_to?(:default_domain)
      gss_alias << ", ntlm_type3_status=#{gss_provider.ntlm_type3_status&.name}" if gss_provider.respond_to?(:ntlm_type3_status)
      gss_alias << ')'
    end
    "#{(args[0] || '')}-#{(args[1] || '')}-#{args[3] || ''}-#{gss_alias}"
  end

  def alias
    super || "SMB Server"
  end

  def start
    self.listener = Rex::Socket::TcpServer.create(
      'LocalHost'      => self.listen_host,
      'LocalPort'      => self.listen_port,
      'Context'        => self.context,
      'Comm'           => self.comm
    )

    thread_factory = Proc.new do |server_client, &block|
      Rex::ThreadFactory.spawn("SMBServerClient(#{server_client.peerhost}->#{server_client.dispatcher.tcp_socket.localhost})", false, &block)
    end

    @rubysmb_server = RubySMB::Server.new(
      server_sock: self.listener,
      gss_provider: @gss_provider,
      logger: @logger,
      thread_factory: thread_factory
    )

    localinfo = Rex::Socket.to_authority(self.listener.localhost, self.listener.localport)
    @listener_thread = Rex::ThreadFactory.spawn("SMBServerListener(#{localinfo})", false) do
      begin
        @rubysmb_server.run do |server_client|
          on_client_connect_proc.call(server_client) if on_client_connect_proc
          true
        end
      rescue IOError => e
        # this 'IOError: stream closed in another thread' is expected, so disregard it
        wlog("#{e.class}: #{e.message}")
      end
    end
  end

  def stop
    self.listener.close
  end

  def wait
    @listener_thread.join if @listener_thread
  end

  attr_accessor :context, :comm, :listener, :listen_host, :listen_port, :on_client_connect_proc
end

end
end
end
