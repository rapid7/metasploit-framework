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

    def abort_foreground_supported
      false
    end

    def shell_command_token_unix(cmd, timeout=10)
      res = super

      res.gsub!("\r\n", "\n") if res
      res
    end

    def initialize(conn, opts=nil)
      super

      if opts && (ssm_peer_info = opts.fetch(:aws_ssm_host_info))
        case ssm_peer_info['PlatformType']
        when 'Linux'
          @platform = 'linux'
          @session_type = 'shell'
        when 'MacOS'
          @platform = 'osx'
          @session_type = 'shell'
        when 'Windows'
          @platform = 'windows'
          @session_type = 'powershell:winpty'
          extend(Msf::Sessions::PowerShell::Mixin)
        end

        @info = "AWS SSM #{ssm_peer_info['ResourceType']} (#{ssm_peer_info['InstanceId']})"
      end
    end

    def type
      @session_type.dup
    end

    def bootstrap(*args)
      if @platform == 'linux'
        # The session from SSM-SessionManagerRunShell starts with a TTY which breaks the post API so change the settings
        # and make it behave in a way consistent with other shell sessions
        shell_command('stty -echo cbreak;pipe=$(mktemp -u);mkfifo -m 600 $pipe;cat $pipe & sh 1>$pipe 2>$pipe; rm $pipe; exit')
      end

      super
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
