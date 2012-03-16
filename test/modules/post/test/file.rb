require 'module_test'
load 'lib/msf/core/post/file.rb'

class Metasploit4 < Msf::Post

	include Msf::ModuleTest::PostTest
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

		it "should create files" do
			write_file("pwned", "foo")

			file_exist?("pwned")
		end

		it "should read files" do
			read_file("pwned") == "foo"
		end

		it "should append files" do
			ret = true
			append_file("pwned", "bar")

			ret &&= read_file("pwned") == "foobar"
			append_file("pwned", "baz")
			ret &&= read_file("pwned") == "foobarbaz"

			ret
		end

		it "should delete files" do
			file_rm("pwned")

			not file_exist?("pwned")
		end

	end

end

