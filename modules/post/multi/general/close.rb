##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

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
