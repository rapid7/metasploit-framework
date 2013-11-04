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
class Console::CommandDispatcher::Lanattacks

  require 'rex/post/meterpreter/ui/console/command_dispatcher/lanattacks/dhcp'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/lanattacks/tftp'

  Klass = Console::CommandDispatcher::Lanattacks

  Dispatchers =
    [
      Klass::Dhcp,
      Klass::Tftp
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
    "Lanattacks extension"
  end

end

end
end
end
end
