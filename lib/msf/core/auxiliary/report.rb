module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report


	def initialize(info = {})
		super
	end

	# Shortcut method for detecting when the DB is active
	def db
		framework.db.active
	end

	def myworkspace
		return @myworkspace if @myworkspace
		@myworkspace = framework.db.find_workspace(self.workspace)
	end

	#
	# Report a host's liveness and attributes such as operating system and service pack
	#
	# opts must contain :host, which is an IP address identifying the host
	# you're reporting about
	#
	# See data/sql/*.sql and lib/msf/core/db.rb for more info
	#
	def report_host(opts)
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_host(opts)
	end

	def get_host(opts)
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.get_host(opts)
	end

	#
	# Report a client connection
	#
	# opts must contain
	#	:host      the address of the client connecting
	#	:ua_string a string that uniquely identifies this client
	# opts can contain
	#	:ua_name a brief identifier for the client, e.g. "Firefox"
	#	:ua_ver  the version number of the client, e.g. "3.0.11"
	#
	def report_client(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_client(opts)
	end

	def get_client(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.get_client(opts)
	end

	#
	# Report detection of a service
	#
	def report_service(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_service(opts)
	end

	def report_note(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_note(opts)
	end

	def report_auth_info(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_auth_info(opts)
	end

	def report_vuln(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_vuln(opts)
	end

	def report_exploit(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_exploit(opts)
	end

	def report_loot(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_loot(opts)
	end

	def report_web_site(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_web_site(opts)
	end
	
	def report_web_page(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_web_page(opts)
	end	
	
	def report_web_form(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_web_form(opts)
	end	
	
	def report_web_vuln(opts={})
		return if not db
		opts = {:workspace => myworkspace}.merge(opts)
		framework.db.report_web_vuln(opts)
	end	

	def store_loot(ltype, ctype, host, data, filename=nil, info=nil)
		if ! ::File.directory?(Msf::Config.loot_directory)
			FileUtils.mkdir_p(Msf::Config.loot_directory)
		end

		# Allow either a session or host to be specified
		if host.respond_to?('target_host')
			thost = host.target_host
			tpeer = host.tunnel_peer
			if tpeer and (!thost or thost.empty?)
				thost = tpeer.split(":")[0]
			end
			host = thost
		end
		
		ext = 'bin'
		if filename
			exts = filename.to_s.split('.')
			if exts.length > 1 and exts[-1].length < 4
				ext = exts[-1]
			end
		end

		case ctype
		when "text/plain"
			ext = "txt"
		end

		name =
			Time.now.strftime("%Y%m%d%H%M%S") + "_" +
			myworkspace.name[0,16] + "_" + (host || 'unknown') + '_' +
			ltype[0,16] + '_' + Rex::Text.rand_text_numeric(6) + '.' + ext


		name.gsub!(/[^a-z0-9\.\_]+/i, '')

		path = File.join(Msf::Config.loot_directory, name)
		conf = {}
		conf[:host] = host if host
		conf[:type] = ltype
		conf[:content_type] = ctype
		conf[:path] = ::File.expand_path(path)
		conf[:workspace] = myworkspace
		conf[:name] = filename if filename
		conf[:info] = info if info

		print_status("Writing #{ltype} (#{ctype}) for #{host}: (#{filename} - #{info})...")
		File.open(conf[:path], "wb") do |fd|
			fd.write(data)
		end
		ret_path = conf[:path].dup

		framework.db.report_loot(conf)
		return ret_path
	end

	# Takes a credential from a script (shell or meterpreter), and
	# sources it correctly to the originating user account. Note
	# that if the user account is not already stored as a credential
	# against that service, source_id will end up nil, and will
	# appear as a self-sourced credential the next time credentials are
	# sourced.
	def store_cred(opts={})
		if [opts[:port],opts[:sname]].compact.empty?
			raise ArgumentError, "Missing option: :sname or :port"
		end
		cred_opts = opts
		cred_opts = opts.merge(:workspace => myworkspace)
		cred_host = myworkspace.hosts.find_by_address(cred_opts[:host])
		unless opts[:port]
			possible_services = myworkspace.services.find_all_by_host_id_and_name(cred_host[:id],cred_opts[:sname])
			case possible_services.size
			when 0
				case cred_opts[:sname].downcase
				when "smb"
					cred_opts[:port] = 445
				when "ssh"
					cred_opts[:port] = 22
				when "telnet"
					cred_opts[:port] = 23
				when "snmp"
					cred_opts[:port] = 161
					cred_opts[:proto] = "udp"
				else
					raise ArgumentError, "No matching :sname found to store this cred."
				end
			when 1
				cred_opts[:port] = possible_services.first[:port]
			else # SMB should prefer 445. Everyone else, just take the first hit.
				if (cred_opts[:sname].downcase == "smb") && possible_services.map {|x| x[:port]}.include?(445)
					cred_opts[:port] = 445
				elsif (cred_opts[:sname].downcase == "ssh") && possible_services.map {|x| x[:port]}.include?(22)
					cred_opts[:port] = 22
				else
					cred_opts[:port] = possible_services.first[:port]
				end
			end
		end
		if opts[:collect_user]
			cred_service = cred_host.services.find_by_host_id(cred_host[:id])
			myworkspace.creds.sort {|a,b| a.created_at.to_f}.each do |cred|
				if(cred.user.downcase == opts[:collect_user].downcase &&
				   cred.pass == opts[:collect_pass]
				  )
					cred_opts[:source_id] ||= cred.id
					cred_opts[:source_type] ||= cred_opts[:collect_type]
					break
				end
			end
		end
		if opts[:collect_session]
			exploit = myworkspace.exploited_hosts.find_by_session_uuid(opts[:collect_session])
			if !exploit.nil? 
				cred_opts[:source_id] = exploit.id
				cred_opts[:source_type] = "exploit"
			else 
				# This session isn't in exploited_hosts, so can't attribute. 
			end
		end
		print_status "Collecting #{cred_opts[:user]}:#{cred_opts[:pass]}"
		framework.db.report_auth_info(cred_opts)
	end			
end
end

