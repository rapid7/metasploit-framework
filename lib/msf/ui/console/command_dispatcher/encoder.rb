# -*- coding: binary -*-
module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Command dispatcher for encoder modules.
#
###
class Encoder

  include Msf::Ui::Console::ModuleCommandDispatcher

  #
  # Returns the name of the command dispatcher.
  #
  def name
    "Encoder"
  end

  #
  # Encoder's don't currently have a user interface.
  #
  def commands
    { }
  end

end

end end end end
