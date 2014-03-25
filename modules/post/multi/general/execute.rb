##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Generic Operating System Session Command Execution',
      'Description'   => %q{ This module executes an arbitrary command line},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'hdm' ],
      'Platform'      => %w{ linux osx unix win },
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))
    register_options(
      [
        OptString.new( 'COMMAND', [false, 'The entire command line to execute on the session'])
      ], self.class)
  end

  def run
    print_status("Executing #{datastore['COMMAND']} on #{session.inspect}...")
    res = cmd_exec(datastore['COMMAND'])
    print_status("Response: #{res}")

  end

end
