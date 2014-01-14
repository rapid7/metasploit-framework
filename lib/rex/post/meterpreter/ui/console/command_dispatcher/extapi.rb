# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Extended API user interface.
#
###
class Console::CommandDispatcher::Extapi

  require 'rex/post/meterpreter/ui/console/command_dispatcher/extapi/window'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/extapi/service'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/extapi/clipboard'

  Klass = Console::CommandDispatcher::Extapi

  Dispatchers =
    [
      Klass::Window,
      Klass::Service,
      Klass::Clipboard
    ]

  include Console::CommandDispatcher

  #
  # Initializes an instance of the extended API command interaction.
  #
  def initialize(shell)
    super

    Dispatchers.each { |d| shell.enstack_dispatcher(d) }
  end

  #
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
    "Extended API Extension"
  end

end

end
end
end
end
