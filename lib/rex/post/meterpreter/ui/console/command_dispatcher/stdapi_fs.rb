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
class Console::CommandDispatcher::Stdapi_Fs

  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/fs'
  Klass = Console::CommandDispatcher::Stdapi_Fs

  Dispatchers =
    [
      Console::CommandDispatcher::Stdapi::Fs,
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
    "Standard FS extension"
  end

end

end
end
end
end
