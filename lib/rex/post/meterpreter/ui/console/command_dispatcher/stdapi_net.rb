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
class Console::CommandDispatcher::Stdapi_Net

  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/net'

  Klass = Console::CommandDispatcher::Stdapi_Net

  Dispatchers =
    [
      Console::CommandDispatcher::Stdapi::Net,
    ]

  include Console::CommandDispatcher

  def self.has_command?(name)
    Dispatchers.any? { |klass| klass.has_command?(name) }
  end

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
    "Standard Net extension"
  end

end

end
end
end
end
