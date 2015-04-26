# -*- coding: binary -*-
require 'msf/base/sessions/command_shell'

class Msf::Sessions::PowerShell < Msf::Sessions::CommandShell

  #
  # Returns the type of session.
  #
  def self.type
    "powershell"
  end

  #
  # Returns the session description.
  #
  def desc
    "Powershell session"
  end
end
