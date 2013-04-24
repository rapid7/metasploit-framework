require 'msf/core'
require 'msf/core/post/windows/accounts'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Shock and Awe',
			'Description'   => %q{
					Donald Rumsfeld
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'DJ Manila Ice', 'Ian Parker', 'crymsen', 'porkchop', 'BMack'], 
			'Version'       => '1',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		register_options(
                        [
                                OptString.new(   'COMMAND',  [false, 'COMMAND String to execute specific Shock and Awe functionality']),
                                OptString.new(   'PATH',  [false, 'PATH String to specify directory for an action']),
                        ], self.class)
	end

	def run
		if datastore["COMMAND"].eql? "goat"
			the_goat
		elsif datastore["COMMAND"].eql? "turkey"
			the_turkey	
		elsif datastore["COMMAND"].eql? "bluewaffle"
			bluewaffle
		end
	end
	
	def the_goat
	end
	
	def the_turkey
	end

	def bluewaffle 
	end

end
