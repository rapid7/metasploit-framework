# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Lua extension user interface.
#
###
class Console::CommandDispatcher::Lua

  Klass = Console::CommandDispatcher::Lua

  include Console::CommandDispatcher

  #
  # Initializes an instance of the lua command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "lua_dostring" => "Execute provided string"
    }
  end

  def cmd_lua_dostring(*args)
    code = args[0]
    if (code == 0)
      print_error("Usage: lua_dostring [string]")
      return
    end
    
    client.lua.execute(code)
  end

  #
  # Name for this dispatcher
  #
  def name
    "Lua"
  end

end

end
end
end
end
