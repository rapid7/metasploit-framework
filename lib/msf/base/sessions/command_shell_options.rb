# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/
##


module Msf
module Sessions
module CommandShellOptions

  def initialize(info = {})
    super(info)

    register_advanced_options(
      [
        OptString.new('InitialAutoRunScript', "An initial script to run on session creation (before AutoRunScript)"),
        OptString.new('AutoRunScript', "A script to run automatically on session creation."),
        OptString.new('CommandShellCleanupCommand', "A command to run before the session is closed")
      ]
    )
  end

  def on_session(session)
    super

    # Configure input/output to match the payload
    session.user_input  = self.user_input if self.user_input
    session.user_output = self.user_output if self.user_output
    if self.platform and self.platform.kind_of? Msf::Module::PlatformList
      session.platform = self.platform.platforms.first.realname.downcase
    end
    if self.platform and self.platform.kind_of? Msf::Module::Platform
      session.platform = self.platform.realname.downcase
    end

    if self.arch
      if self.arch.kind_of?(Array)
        session.arch = self.arch.join('')
      else
        session.arch = self.arch
      end
    end

  end

end
end
end
