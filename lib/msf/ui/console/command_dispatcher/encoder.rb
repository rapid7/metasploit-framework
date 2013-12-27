# -*- coding: binary -*-

# Command dispatcher for encoder modules.
class Msf::Ui::Console::CommandDispatcher::Encoder
  include Msf::Ui::Console::ModuleCommandDispatcher

  # Returns the name of the command dispatcher.
  #
  # @return [String]
  def name
    "Encoder"
  end
end
