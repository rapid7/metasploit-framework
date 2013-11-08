# $Id$
# $Revision$
# Author: 
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client
sample_option_var = nil
@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-o" => [ true , "Option that requieres a value"]
  )
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
  print_line "Meterpreter Script for INSERT PURPOSE."
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
  print_error("#{meter} version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end

################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-o"
    sample_option_var = val
  end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64|java|php|linux/i # Remove none supported versions
