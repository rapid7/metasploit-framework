##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'

###
#
# This post module sample shows how we can execute a command on the compromised machine
#
###
class Metasploit4 < Msf::Post

  include Msf::Post::Common

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Sample Post Module',
      'Description'   => %q{Sample Post Module},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'win'],
      'SessionTypes'  => [ "shell", "meterpreter" ]
    ))
  end

  #
  # This post module runs a ipconfig command and returns the output
  #
  def run
    print_status("Executing ipconfig on remote machine")
    o = cmd_exec("ipconfig")
    print_line(o)
  end

end