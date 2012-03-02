
require 'msf/core'
require 'rex'

$:.push "test/lib" unless $:.include? "test/lib"
#require 'module_test'
load 'test/lib/module_test.rb'

load 'lib/rex/post/meterpreter/extensions/stdapi/fs/dir.rb'

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
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")

		test_sys_config
		test_net_config
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
			wd = session.fs.dir.pwd
			vprint_status("CWD: #{wd}")

			true
		end

		it "should list files in the current directory" do
			session.fs.dir.entries
		end

		it "should stat a directory" do
			session.fs.file.stat(session.fs.dir.pwd).directory?
		end

		it "should create and remove a dir" do
			res = create_directory("meterpreter-test")
			if (res)
				session.fs.dir.rmdir("meterpreter-test")
				res &&= !session.fs.dir.entries.include?("meterpreter-test")
				vprint_status("Directory removed successfully")
			end

			res
		end

		it "should change directories" do
			res = create_directory("meterpreter-test")

			old_wd = session.fs.dir.pwd
			vprint_status("Old CWD: #{old_wd}")

			if res
				session.fs.dir.chdir("meterpreter-test")
				new_wd = session.fs.dir.pwd
				vprint_status("New CWD: #{new_wd}")
				res &&= (new_wd =~ /meterpreter-test$/)

				if res
					session.fs.dir.chdir("..")
					wd = session.fs.dir.pwd
					vprint_status("Back to old CWD: #{wd}")
				end
			end
			session.fs.dir.rmdir("meterpreter-test")
			res &&= !session.fs.dir.entries.include?("meterpreter-test")
			vprint_status("Directory removed successfully")

			res
		end

		it "should create and remove files" do
			res = true
			fd = session.fs.file.new("meterpreter-test", "wb")
			fd.write("test")
			fd.close

			vprint_status("Wrote to meterpreter-test, checking contents")
			fd = session.fs.file.new("meterpreter-test", "rb")
			contents = fd.read
			vprint_status("Wrote #{contents}")
			p fd
			res &&= (contents == "test")
			fd.close

			session.fs.file.rm("meterpreter-test")
			res &&= !session.fs.dir.entries.include?("meterpreter-test")

			res
		end

	end

	def create_directory(name)
		res = true

		session.fs.dir.mkdir(name)
		entries = session.fs.dir.entries
		res &&= entries.include?(name)
		res &&= session.fs.file.stat(name).directory?
		if res
			vprint_status("Directory created successfully")
		end

		res
	end

end
