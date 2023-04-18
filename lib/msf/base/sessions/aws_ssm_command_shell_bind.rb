# -*- coding: binary -*-

module Msf::Sessions
  ###
  #
  # This class provides basic interaction with an AWS SSM
  # session socket encapsulated by a
  # Rex::Proto::Http::WebSocket::AmazonSsm::Interface::SsmChannel
  #
  #  Date:    Feb 4, 2023
  #  Author:  RageLtMan
  #
  ###
  class AwsSsmCommandShellBind < Msf::Sessions::CommandShell

    #
    # This interface supports basic interaction.
    #
    include Msf::Session::Basic

    #
    # This interface supports interacting with a single command shell.
    #
    include Msf::Session::Provider::SingleCommandShell

    def initialize(conn, opts=nil)
      super

      if opts && (ssm_peer_info = opts.fetch(:aws_ssm_host_info))
        case ssm_peer_info['PlatformType']
        when 'Linux'
          @platform = 'linux'
        when 'MacOS'
          @platform = 'osx'
        when 'Windows'
          @platform = 'win'
        end

        @info = "AWS SSM #{ssm_peer_info['ResourceType']} (#{ssm_peer_info['InstanceId']})"
      end
    end

    ##
    #
    # Returns the session description.
    #
    def desc
      'AWS SSM command shell'
    end
  end
end
