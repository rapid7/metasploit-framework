#require 'module_test'
load 'test/lib/module_test.rb'
#load 'lib/rex/text.rb'
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

		it "should read the text we just wrote" do
			f = read_file("pwned")
			ret = ("foo" == f)
			unless ret
				print_error("Didn't read what we wrote, actual file on target: #{f}")
			end

			ret
		end

		it "should append text files" do
			ret = true
			append_file("pwned", "bar")

			ret &&= read_file("pwned") == "foobar"
			append_file("pwned", "baz")
			final_contents = read_file("pwned")
			ret &&= final_contents == "foobarbaz"
			unless ret
				print_error("Didn't read what we wrote, actual file on target: #{final_contents}")
			end

			ret
		end

		it "should delete text files" do
			file_rm("pwned")

			not file_exist?("pwned")
		end

	end

	def test_binary_files

		#binary_data = ::File.read("/bin/ls")
		binary_data = ::File.read("/bin/echo")
		#binary_data = "\xff\x00\xff\xfe\xff\`$(echo blha)\`"
		it "should write binary data" do
			vprint_status "Writing #{binary_data.length} bytes"
			t = Time.now
			write_file("pwned", binary_data)
			vprint_status("Finished in #{Time.now - t}")

			file_exist?("pwned")
		end

		it "should read the binary data we just wrote" do
			bin = read_file("pwned")
			vprint_status "Read #{bin.length} bytes"

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

