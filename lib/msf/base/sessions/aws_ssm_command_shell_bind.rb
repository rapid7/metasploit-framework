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

    ##
    #
    # Returns the session description.
    #
    def desc
      'AWS SSM command shell'
    end

    ##
    # Intercept point from Msf::Sessions::CommandShell#shell_read
    ##
    def shell_read(length=-1, timeout=1)
      super(length, timeout)
    end

    ##
    # Intercept point from Msf::Sessions::CommandShell#shell_write
    ##
    def shell_write(buf)
      super(buf)
    end
  end
end
