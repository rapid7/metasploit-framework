
require 'msf/core'
require 'rex'

$:.push "test/lib" unless $:.include? "test/lib"
#require 'module_test'
load 'test/lib/module_test.rb'


class Metasploit3 < Msf::Post

	include Msf::ModuleTest

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Testing ',
				'Description'   => %q{ This module will test windows services methods within a shell},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'egypt'],
				'Version'       => '$Revision: 11663 $',
				'Platform'      => [ 'windows', 'linux' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

	end

	def run
		blab = datastore['VERBOSE']
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")

		it "should return a user id" do
			uid = session.sys.config.getuid
			true
		end

		it "should return a sysinfo Hash" do
			sysinfo = session.sys.config.sysinfo
			true
		end

		it "should return network interfaces" do
			ifaces = session.net.config.get_interfaces

			ifaces and ifaces.length > 0
		end

		print_status("Testing complete.")
	end

end
