# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Standard API extension.
#
###
class Console::CommandDispatcher::Stdapi


  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/fs'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/net'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/sys'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/ui'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/webcam'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/mic'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/corrm_apps'

  Klass = Console::CommandDispatcher::Stdapi

  Dispatchers =
    [
      Klass::Fs,
      Klass::Net,
      Klass::Sys,
      Klass::Ui,
      Klass::Webcam,
      Klass::Mic,
      Klass::CorrMApps
    ]

  include Console::CommandDispatcher

  #
  # Initializes an instance of the stdapi command interaction.
  #
  def initialize(shell)
    super

    Dispatchers.each { |d|
      shell.enstack_dispatcher(d)
    }
  end

  #
  # List of supported commands.
  #
  def commands
    {
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Standard extension"
  end

end

end
end
end
end
