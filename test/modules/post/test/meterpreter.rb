
require 'msf/core'
require 'rex'

$:.push "test/lib" unless $:.include? "test/lib"
#require 'module_test'
load 'test/lib/module_test.rb'


class Metasploit3 < Msf::Post

	include Msf::ModuleTest

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Testing meterpreter stuff',
				'Description'   => %q{ This module will test meterpreter API methods },
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

		#test_sys_config
		#test_net_config
		test_fs

		print_status("Testing complete.")
	end

	def test_sys_config
		it "should return a user id" do
			uid = session.sys.config.getuid
			true
		end

		it "should return a sysinfo Hash" do
			sysinfo = session.sys.config.sysinfo
			true
		end
	end

	def test_net_config
		it "should return network interfaces" do
			ifaces = session.net.config.get_interfaces

			ifaces and ifaces.length > 0
		end
	end

	def test_fs

		it "should return the current working directory" do
			wd = session.fs.dir.getwd
			vprint_status("CWD: #{wd}")

			true
		end

		it "should list files in the current directory" do
			session.fs.dir.entries
		end

		it "should create and remove a dir" do
			res = true
			session.fs.dir.mkdir("meterpreter-test")
			entries = session.fs.dir.entries
			res = entries.include?("meterpreter-test")
			if (res)
				vprint_status("Directory created successfully")
				session.fs.dir.rmdir("meterpreter-test")
				res = !session.fs.dir.entries.include?("meterpreter-test")
				vprint_status("Directory removed successfully")
			end

			res
		end

		it "should change directories" do
			res = true
			session.fs.dir.mkdir("meterpreter-test")
			entries = session.fs.dir.entries
			res = entries.include?("meterpreter-test")
			if (res)
				vprint_status("Directory created successfully")
				session.fs.dir.chdir("meterpreter-test")
				wd = session.fs.dir.getwd
				vprint_status("New CWD: #{wd}")
				session.fs.dir.chdir("..")
				vprint_status("Back to old CWD: #{wd}")
				session.fs.dir.rmdir("meterpreter-test")
				res = !session.fs.dir.entries.include?("meterpreter-test")
				vprint_status("Directory removed successfully")
			end

			res
		end

	end

end
