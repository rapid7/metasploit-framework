# -*- coding: binary -*-
require 'rex/proto/ssh/connection'

module Rex
module Proto
module Ssh
###
#
# Runtime extension of the SSH clients that connect to the server.
#
###

module ServerClient
  #
  # Initialize a new connection instance.
  #
  def init_cli(server, do_not_start = false)
    @server          = server
    @connection      = Rex::Proto::Ssh::Connection.new(
      self, server.server_options.merge(ssh_server: server), server.context
    )
    @connection_thread = Rex::ThreadFactory.spawn("SshConnectionMonitor-#{self}", false) {
      self.connection.start
    } unless do_not_start
  end

  def close
    @connection_thread.kill if @connection_thread and @connection_thread.alive?
    super
  end

  attr_reader :connection, :server
end

###
#
# Acts as an SSH server, accepting clients and extending them with Connections
#
###
class Server

  include Proto
  #
  # Initializes an SSH server as listening on the provided port and
  # hostname.
  #
  def initialize(port = 22, listen_host = '0.0.0.0', context = {}, comm = nil,
    ssh_opts = Ssh::Connection.default_options, cc_cb = nil, cd_cb = nil)

    self.listen_host            = listen_host
    self.listen_port            = port
    self.context                = context
    self.comm                   = comm
    self.listener               = nil
    self.server_options         = ssh_opts
    self.on_client_connect_proc = cc_cb
    self.on_client_data_proc    = cd_cb
  end

  # More readable inspect that only shows the url and resources
  # @return [String]
  def inspect
    "#<#{self.class} ssh://#{listen_host}:#{listen_port}>"
  end

  #
  # Returns the hardcore alias for the SSH service
  #
  def self.hardcore_alias(*args)
    "#{(args[0])}#{(args[1])}"
  end

  #
  # SSH server.
  #
  def alias
    super || "SSH Server"
  end


  #
  # Listens on the defined port and host and starts monitoring for clients.
  #
  def start(srvsock = nil)

    self.listener = srvsock.is_a?(Rex::Socket::TcpServer) ? srvsock : Rex::Socket::TcpServer.create(
      'LocalHost' => self.listen_host,
      'LocalPort' => self.listen_port,
      'Context'   => self.context,
      'Comm'      => self.comm
    )

    # Register callbacks
    self.listener.on_client_connect_proc = Proc.new { |cli|
      on_client_connect(cli)
    }
    # self.listener.on_client_data_proc = Proc.new { |cli|
    #   on_client_data(cli)
    # }
    self.clients         = []
    self.monitor_thread  = Rex::ThreadFactory.spawn("SshServerClientMonitor", false) {
      monitor_clients
    }
    self.listener.start
  end

  #
  # Terminates the monitor thread and turns off the listener.
  #
  def stop
    self.listener.stop
    self.listener.close
    self.clients = []
  end


  #
  # Waits for the SSH service to terminate
  #
  def wait
    self.listener.wait if self.listener
  end

  #
  # Closes the supplied client, if valid.
  #
  def close_client(cli)
    clients.delete(cli)
    listener.close_client(cli.parent)
  end


  attr_accessor :listen_port, :listen_host, :context, :comm, :clients, :monitor_thread
  attr_accessor :listener, :server_options, :on_client_connect_proc, :on_client_data_proc

protected

  #
  # Extends new clients with the ServerClient module and initializes them.
  #
  def on_client_connect(cli)
    cli.extend(ServerClient)

    cli.init_cli(self)
    if self.on_client_connect_proc
      self.on_client_connect_proc.call(cli)
    else
      enqueue_client(cli)
    end
  end

  #
  # Watches FD channel abstractions, removes closed instances,
  # checks for read data on clients if client data callback is defined,
  # invokes the callback if possible, sleeps otherwise.
  #
  def monitor_clients
    loop do
      self.clients.delete_if {|c| c.closed? }
      if self.on_client_data_proc
        if clients.any? { |cli|
          cli.has_read_data? and self.on_client_data_proc.call(cli)}
          next
        else
          sleep 0.05
        end
      else
        sleep 0.5
      end
    end
  rescue => e
    wlog(e)
  end

  #
  # Waits for SSH client to "grow a pair" of FDs and adds
  # a ChannelFD object derived from the client's Connection
  # Channel's FDs to the Ssh::Server's clients array
  #
  # @param cli [Rex::Proto::Ssh::ServerClient] SSH client
  #
  def enqueue_client(cli)
    Rex::ThreadFactory.spawn("ChannelFDWaiter", false) do
      begin
        Timeout::timeout(15) do
          while cli.connection.open_channel_keys.empty? do
            sleep 0.02
          end
          self.clients.push(Ssh::ChannelFD.new(cli))
        end
      rescue Timeout::Error
        elog("Unable to find channel FDs for client #{cli}")
      end
    end
  end

end

end
end
end
