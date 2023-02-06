# -*- coding: binary -*-

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
  class AwsInstanceConnectBind < Msf::Sessions::SshCommandShellBind
    #
    # Create a sessions instance from an SshConnection. This will handle creating
    # a new command stream.
    #
    # @param ssh_connection [Net::SSH::Connection] The SSH connection to create a
    #   session instance for.
    # @param opts [Hash] Optional parameters to pass to the session object.
    def initialize(ssh_connection, opts = {})
      @peer_info = ssh_connection.transport.socket.peerinfo
      @local_info = ssh_connection.transport.socket.localinfo
      super(ssh_connection, opts)
    end

    #
    # Accessor method for SSH session user
    #
    def username
      @ssh_connection.options[:user]
    end

    ##
    #
    # Returns the session description.
    #
    def desc
      'AWS Instance Connect serial/SSH shell'
    end

    def bootstrap(datastore = {}, handler = nil)
      # Do not manipulate this SSH session at the protocol level - its fragile
      @rstream = Net::SSH::CommandStream.new(ssh_connection).lsock
      @info = "EC2 Instance Connect #{username} @ #{@peer_info}"
      self
    end
  end
end
