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
    print_line
    print_line("                ..:::-::..                ")
    print_line("            -=**##########*+=:.           ")
    print_line("         :  :+#################+-         ")
    print_line("       =*##+:  .=*###############*=       ")
    print_line("     :*#######+-. .:=*#############*:     ")
    print_line("    =############*=:. .....:-=*######=    ")
    print_line("   =########=::+####*          .+#####+   ")
    print_line("  :########-    *###-             ....:   ")
    print_line("  +########:    +###+           .++++==-  ")
    print_line("  *########*.  -#####-         :*#######  ")
    print_line("  *##########*########+-.   .-+#########  ")
    print_line("  *#######################*############*  ")
    print_line("  -#######**##################**#######-  ")
    print_line("   +#####:  =################+  :#####*   ")
    print_line("    +####*:  :+############+:  .*####*    ")
    print_line("     =#####=:   .-=++++=-.   .=#####=     ")
    print_line("      :+#####*=:.        .:=*#####*:      ")
    print_line("        :+########**++**########+:        ")
    print_line("           :=*##############*=-.          ")
    print_line("              .::-==++==-::.              ")
    print_line
    print_line("   TrustedSec COFFLoader (by @kev169, @GuhnooPlusLinux, @R0wdyjoe)")
    print_line

  end

  @@bof_cmd_usage_opts = Arguments.new(
     ['-b', '--bof-file']      => [ true, "Beacon Object File" ],
     ['-a', '--arguments']     => [ false, "List of command-line arguments to pass to the BOF" ],
     ['-f', '--format-string'] => [ false, "bof_pack compatible format-string. Choose combination of: b, i, s, z, Z" ],
  )

  #
  # List of supported commands.
  #
  def commands
    {
      'bof_cmd'              => 'Execute an arbitary BOF file',
    }
  end

  def cmd_bof_cmd_tabs(str, words)
    tab_complete_filenames(str, words)
  end

  def bof_cmd_tabs(*args)
  end
  def cmd_bof_cmd(*args)
    output = client.bofloader.exec_cmd(args)
    if output.nil?
      print_line("Nil output from BOF...")
    else
      print_line(output)
    end

  end

end

end
end
end
end
