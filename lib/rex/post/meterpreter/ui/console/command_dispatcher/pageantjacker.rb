# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

require 'tmpdir'

###
#
# PageantJacker extension 
#
###
class Console::CommandDispatcher::PageantJacker

  Klass = Console::CommandDispatcher::PageantJacker

  include Console::CommandDispatcher

  def initialize(shell)
    super
    print_line
    print_line
	print_line("       .mMMMMMm.             mMMm    M  WWW   W    W  RRRRR")
	print_line("      mMMMMMMMMMMM.            MM   MM    W   W   W    R   R")
	print_line("     /MMMM-    -MM.            MM   MM    W   W   W    R   R")
	print_line("    /MMM.    _  \/  ^          M M M M     W W W W     RRRR")
	print_line("    |M.    aRRr    /W|         M M M M     W W W W     R  R")
	print_line("    \/  .. ^^^   wWWW|         M  M  M      W   W      R   R")
	print_line("       /WW\.  .wWWWW/          M  M  M      W   W      R    R")
	print_line("       |WWWWWWWWWWW/")
	print_line("         .WWWWWW.                  PageantJacker Extension")
    print_line
    print_line(" Use post/windows/manage/forward_pageant to proxy agent requests through Pageant")
    print_line
  end

  #
  # List of supported commands.
  #
  def commands
    {
      # No commands here, bceause everything is done from the POST module
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "PageantJacker"
  end
end

end
end
end
end

