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
class Console::CommandDispatcher::Android

  require 'rex/post/meterpreter/ui/console/command_dispatcher/android/common'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/android/root'


  Klass = Console::CommandDispatcher::Android

  Dispatchers =
    [
      Klass::Common,
      #Klass::Root,

    ]

  include Console::CommandDispatcher

  def initialize(shell)
    super

    Dispatchers.each { |d|
      shell.enstack_dispatcher(d)
    }
    
    #shell.enstack_dispatcher(Klass::Common)

    if client.common.check_root == true
      shell.enstack_dispatcher(Klass::Root)
    end
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
    "Android Standard extension"
  end

end

end
end
end
end
