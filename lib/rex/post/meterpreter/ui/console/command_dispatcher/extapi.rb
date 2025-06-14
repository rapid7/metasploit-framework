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
  require 'rex/post/meterpreter/ui/console/command_dispatcher/extapi/adsi'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/extapi/wmi'

  Klass = Console::CommandDispatcher::Extapi

  Dispatchers =
    [
      Klass::Window,
      Klass::Service,
      Klass::Clipboard,
      Klass::Adsi,
      Klass::Wmi
    ]

  include Console::CommandDispatcher

  def self.has_command?(name)
    Dispatchers.any? { |klass| klass.has_command?(name) }
  end

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
    'Extended API Extension'
  end

end

end
end
end
end
