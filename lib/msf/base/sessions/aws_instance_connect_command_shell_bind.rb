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
      @rstream = Net::SSH::CommandStream.new(ssh_connection).lsock

      if @serial_username.present? || @serial_password.present?
        shell_read(-1)
        shell_write("#{@serial_username}\n")

        prompt = ''
        timeout = @rstream.def_read_timeout
        while timeout > 0 && !prompt.start_with?("#{@serial_username}\r")
          chunk, elapsed_time = Rex::Stopwatch.elapsed_time { shell_read(-1, timeout) }
          prompt << chunk
          timeout -= elapsed_time
        end
        shell_read(-1) # one more time to get the prompt, whatever that may be
        shell_write("#{@serial_password}\n")
      end

      @info = "EC2 Instance Connect #{@serial_username.present? ? @serial_username : ssh_username} @ #{@peer_info}"

      super
    end

    attr_reader :serial_username, :sock, :ssh_connection
  end
end
