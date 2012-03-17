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

		it "should create files" do
			write_file("pwned", "foo")

			file_exist?("pwned")
		end

		it "should read files" do
			f = read_file("pwned")

			"foo" == f
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

	def test_binary_files

		binary_data = "\x00\xff\"'$"
		pending "should write binary data" do
			write_file("binary", binary_data)

			file_exist?("binary")
		end
		pending "should read binary data" do
			bin = read_file("binary")

			bin == binary_data
		end
		pending "should delete binary files" do
			file_rm("pwned")

			not file_exist?("pwned")
		end
	end

	def test_large_files
		[ 1024, 2048, 4096, 8192, 16384, 32768, 65536 ].each { |count|
			pending "should write #{count} bytes" do
				bytes = "A"*count
				write_file("pwned", bytes)

				ret = file_exist?("pwned")
				remote = read_file("pwned")
				ret &&= !!(remote == bytes)
				#file_rm("pwned")

				ret
			end
		}

	end

end

