# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/
##


module Msf
module Sessions
module PingbackOptions

  def initialize(info = {})
    super(info)

    register_advanced_options(
      [
        OptBool.new('CreateSession', [false, 'Create a new session for every successful login', true]),
        OptString.new('InitialAutoRunScript', "An initial script to run on session creation (before AutoRunScript)"),
        OptString.new('AutoRunScript', "A script to run automatically on session creation."),
        OptString.new('CommandShellCleanupCommand', "A command to run before the session is closed"),
        OptInt.new('PingbackRetries', [true, "How many additional successful pingbacks", 0]),
        OptInt.new('PingbackSleep', [true, "Time (in seconds) to sleep between pingbacks", 30])
      ]
    )
  end

  def on_session(session)
    super

    # Configure input/output to match the payload
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
    def generate_pingback_uuid
    puts("generate_pingback_uuid")
    conf = {}
    if datastore['PingbackUUID'].to_s.length > 0
      #
      # TODO- Make this not terrible
      #
      conf[:pingback_uuid] = datastore['PingbackUUID'].to_s
    end
    conf[:pingback_store] = datastore['PingbackUUIDDatabase']
    pingback = Msf::Payload::Pingback.new(conf)
    datastore['PingbackUUID'] ||= pingback.uuid
    #asoto-r7, this is where we write the UUID to the database.
    pingback.uuid
  end

end
end
end
