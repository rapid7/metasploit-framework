# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Kiwi extension - grabs credentials from windows memory (newer OSes).
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by OJ Reeves (TheColonial)
#
###
class Console::CommandDispatcher::Bofloader

  Klass = Console::CommandDispatcher::Bofloader

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Bofloader'
  end

  #
  # Initializes an instance of the priv command interaction. This function
  # also outputs a banner which gives proper acknowledgement to the original
  # author of the Mimikatz software.
  #
  def initialize(shell)
    super
    print_line
    print_line(" Lawd dem BOFS -->  <bof file> <fstring> <args>")
    print_line

  end

  #
  # List of supported commands.
  #
  def commands
    {
      'bof_cmd'              => 'Execute an arbitary BOF file',
    }
  end

  def cmd_bof_cmd(*args)
    print_line("here1")
    output = client.bofloader.exec_cmd(args)
    print_line("here2")
    print_line(output)
  end

end

end
end
end
end
