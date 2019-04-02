# -*- coding: binary -*-
# CorrM @ fb.me/IslamNofl

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
class Console::CommandDispatcher::AppApi

  require 'rex/post/meterpreter/ui/console/command_dispatcher/appapi/android_appapi'

  Klass = Console::CommandDispatcher::AppApi

  Dispatchers =
    [
      Klass::AndroidApps
    ]

  include Console::CommandDispatcher

  #
  # Initializes an instance of the appapi command interaction.
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
    "Appilcation Controller extension"
  end

end

end; end; end; end
