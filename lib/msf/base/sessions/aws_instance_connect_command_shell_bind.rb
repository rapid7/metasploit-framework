# -*- coding: binary -*-

require 'rex/stopwatch'

module Msf::Sessions
  ###
  #
  # This class provides basic interaction with an AWS InstanceConnect
  # session SSH socket
  #
  #  Date:    Feb 5, 2023
  #  Author:  RageLtMan
  #
  ###
  class AwsInstanceConnectCommandShellBind < Msf::Sessions::CommandShell

    #
    # This interface supports basic interaction.
    #
    include Msf::Session::Basic

    #
    # This interface supports interacting with a single command shell.
    #
    include Msf::Session::Provider::SingleCommandShell

    def shell_command_token_unix(cmd, timeout=10)
      res = shell_command_token_base(cmd, timeout, "\n")

      res.gsub!("\r\n", "\n") if res
      res
    end

    def shell_write(buf)
      @ssh_command_stream.channel.send_data(buf)
      # net-ssh queues the data to send to the remote end, wait for it to all be sent to fix stability issues
      while @ssh_command_stream.channel.output.length > 0
        sleep 0.1
      end
    end

    #
    # Create a sessions instance from an SshConnection. This will handle creating
    # a new command stream.
    #
    # @param ssh_connection [Net::SSH::Connection] The SSH connection to create a
    #   session instance for.
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(ssh_connection, opts = {})
      @ssh_connection = ssh_connection
      @sock = ssh_connection.transport.socket

      @peer_info = ssh_connection.transport.socket.peerinfo
      @local_info = ssh_connection.transport.socket.localinfo
      @serial_username = opts[:serial_username]
      @serial_password = opts[:serial_password]
      self.platform = 'unix'
      super(nil, opts)
    end

    #
    # Accessor method for SSH session user
    #
    def ssh_username
      @ssh_connection.options[:user]
    end

    alias username ssh_username

    ##
    #
    # Returns the session description.
    #
    def desc
      'AWS Instance Connect serial/SSH shell'
    end

    def bootstrap(datastore = {}, handler = nil)
      @ssh_command_stream = Net::SSH::CommandStream.new(ssh_connection)

      @ssh_command_stream.verify_channel
      # set remote_window_size to 32 which seems to help stability
      @ssh_command_stream.channel.do_window_adjust(-@ssh_command_stream.channel.remote_window_size + 32)
      @rstream = @ssh_command_stream.lsock

      if @serial_username.present? || @serial_password.present?
        shell_write("#{@serial_username}\n")
        shell_write("#{@serial_password}\n")
      end

      shell_command('stty -echo cbreak;pipe=$(mktemp -u);mkfifo -m 600 $pipe;cat $pipe & sh 1>$pipe 2>$pipe; rm $pipe; exit')
      shell_read(-1)

      @info = "EC2 Instance Connect #{@serial_username.present? ? @serial_username : ssh_username} @ #{@peer_info}"

      super
    end

    def cleanup
      super

      ssh_connection.close rescue nil
    end

    attr_reader :serial_username, :sock, :ssh_connection
  end
end
