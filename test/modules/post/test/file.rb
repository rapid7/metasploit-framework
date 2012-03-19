#require 'module_test'
load 'test/lib/module_test.rb'
load 'lib/msf/core/post/file.rb'

class Metasploit4 < Msf::Post

	include Msf::ModuleTest::PostTest
	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Testing remote file manipulation',
				'Description'   => %q{ This module will test Post::File API methods },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'egypt'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows', 'linux', 'java' ],
				'SessionTypes'  => [ 'meterpreter', 'shell' ]
			))
	end

	def test_file
		it "should test for existence" do
			ret = false
			[
				"c:\\boot.ini",
				"c:\\pagefile.sys",
				"/etc/passwd",
				"/etc/master.passwd"
			].each { |file|
				ret = true if file_exist?(file)
			}

			ret
		end

		it "should create text files" do
			write_file("pwned", "foo")

			file_exist?("pwned")
		end

		it "should read text files" do
			f = read_file("pwned")

			"foo" == f
		end

		it "should append text files" do
			ret = true
			append_file("pwned", "bar")

			ret &&= read_file("pwned") == "foobar"
			append_file("pwned", "baz")
			ret &&= read_file("pwned") == "foobarbaz"

			ret
		end

		it "should delete text files" do
			file_rm("pwned")

			not file_exist?("pwned")
		end

	end

	def test_binary_files

		binary_data = ::File.read("/bin/ls")
		#binary_data = "\x00\xff\"'$\nasdfjkl;`foo"*10
		it "should write binary data" do
			vprint_status "Writing #{binary_data.length} bytes"
			t = Time.now
			write_file("pwned", binary_data)
			vprint_status("Finished in #{Time.now - t}")

			file_exist?("pwned")
		end

		it "should read binary data" do
			bin = read_file("pwned")

			bin == binary_data
		end

		it "should delete binary files" do
			file_rm("pwned")

			not file_exist?("pwned")
		end

		it "should append binary data" do
			write_file("pwned", "\xde\xad")
			append_file("pwned", "\xbe\xef")
			bin = read_file("pwned")
			file_rm("pwned")

			bin == "\xde\xad\xbe\xef"
		end

	end

end

