##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Generic Operating System Session Close',
      'Description'   => %q{ This module closes the specified session. This can be useful as a finisher for automation tasks },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'hdm' ],
      'Platform'      => %w{ linux osx unix win },
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))
  end

  def run
    print_status("Closing session #{session.inspect}...")
    session.kill
  end

end
