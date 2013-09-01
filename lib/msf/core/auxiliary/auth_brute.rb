# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for brute forcing authentication
#
###

module Auxiliary::AuthBrute

	def initialize(info = {})
		super

		register_options([
			OptString.new('USERNAME', [ false, 'A specific username to authenticate as' ]),
			OptString.new('PASSWORD', [ false, 'A specific password to authenticate with' ]),
			OptPath.new('USER_FILE', [ false, "File containing usernames, one per line" ]),
			OptPath.new('PASS_FILE', [ false, "File containing passwords, one per line" ]),
			OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line" ]),
			OptInt.new('BRUTEFORCE_SPEED', [ true, "How fast to bruteforce, from 0 to 5", 5]),
			OptBool.new('VERBOSE', [ true, "Whether to print output for all attempts", true]),
			OptBool.new('BLANK_PASSWORDS', [ false, "Try blank passwords for all users", true]),
			OptBool.new('USER_AS_PASS', [ false, "Try the username as the password for all users", true]),
			OptBool.new('DB_ALL_CREDS', [false,"Try each user/password couple stored in the current database",true]),
			OptBool.new('DB_ALL_USERS', [false,"Add all users in the current database to the list",false]),
			OptBool.new('DB_ALL_PASS', [false,"Add all passwords in the current database to the list",false]),
			OptBool.new('STOP_ON_SUCCESS', [ true, "Stop guessing when a credential works for a host", false]),
		], Auxiliary::AuthBrute)

		register_advanced_options([
			OptBool.new('REMOVE_USER_FILE', [ true, "Automatically delete the USER_FILE on module completion", false]),
			OptBool.new('REMOVE_PASS_FILE', [ true, "Automatically delete the PASS_FILE on module completion", false]),
			OptBool.new('REMOVE_USERPASS_FILE', [ true, "Automatically delete the USERPASS_FILE on module completion", false]),
			OptInt.new('MaxGuessesPerService', [ false, "Maximum number of credentials to try per service instance. If set to zero or a non-number, this option will not be used.", 0]), # Tracked in @@guesses_per_service
			OptInt.new('MaxMinutesPerService', [ false, "Maximum time in minutes to bruteforce the service instance. If set to zero or a non-number, this option will not be used.", 0]), # Tracked in @@brute_start_time
			OptInt.new('MaxGuessesPerUser', [ false, %q{
				Maximum guesses for a particular username for the service instance.
				Note that users are considered unique among different services, so a
				user at 10.1.1.1:22 is different from one at 10.2.2.2:22, and both will
				be tried up to the MaxGuessesPerUser limit.	If set to zero or a non-number,
				this option will not be used.}.gsub(/[\t\r\n\s]+/nm,"\s"), 0]) # Tracked in @@brute_start_time
		], Auxiliary::AuthBrute)


	end

	def setup
		@@max_per_service = nil
	end

	# Checks all three files for usernames and passwords, and combines them into
	# one credential list to apply against the supplied block. The block (usually
	# something like do_login(user,pass) ) is responsible for actually recording
	# success and failure in its own way; each_user_pass() will only respond to
	# a return value of :done (which will signal to end all processing) and
	# to :next_user (which will cause that username to be skipped for subsequent
	# password guesses). Other return values won't affect the processing of the
	# list.
	#
	# The 'noconn' argument should be set to true if each_user_pass is merely
	# iterating over the usernames and passwords and should not respect
	# bruteforce_speed as a delaying factor.
	def each_user_pass(noconn=false,&block)
		this_service = [datastore['RHOST'],datastore['RPORT']].join(":")
		fq_rest = [this_service,"all remaining users"].join(":")

		# This should kinda halfway be in setup, halfway in run... need to
		# revisit this.
		unless credentials ||= false # Assignment and comparison!
			credentials ||= build_credentials_array()
			credentials = adjust_credentials_by_max_user(credentials)
			this_service = [datastore['RHOST'],datastore['RPORT']].join(":")
			initialize_class_variables(this_service,credentials)
		end

		credentials.each do |u, p|
			# Explicitly be able to set a blank (zero-byte) username by setting the
			# username to <BLANK>. It's up to the caller to handle this if it's not
			# allowed or if there's any special handling needed (such as smb_login).
			u = "" if u =~ /^<BLANK>$/i
			break if @@credentials_skipped[fq_rest]

			fq_user = [this_service,u].join(":")

			# Set noconn to indicate that in this case, each_user_pass
			# is not actually kicking off a connection, so the
			# bruteforce_speed datastore should be ignored.
			if not noconn
				userpass_sleep_interval unless @@credentials_tried.empty?
			end

			next if @@credentials_skipped[fq_user]
			next if @@credentials_tried[fq_user] == p

			ret = block.call(u, p)

			case ret
			when :abort # Skip the current host entirely.
				abort_msg = {
					:level => :error,
					:ip => datastore['RHOST'],
					:port => datastore['RPORT'],
					:msg => "Bruteforce cancelled against this service."
				}
				unless datastore['VERBOSE']
					abort_msg[:msg] << " Enable verbose output for service-specific details."
				end
				print_brute abort_msg
				break

			when :next_user # This means success for that user.
				@@credentials_skipped[fq_user] = p
				if datastore['STOP_ON_SUCCESS'] # See?
					@@credentials_skipped[fq_rest] = true
				end

			when :skip_user # Skip the user in non-success cases.
				@@credentials_skipped[fq_user] = p

			when :connection_error # Report an error, skip this cred, but don't neccisarily abort.
				print_brute(
					:level => :verror,
					:ip => datastore['RHOST'],
					:port => datastore['RPORT'],
					:msg => "Connection error, skipping '#{u}':'#{p}'")
			end

			@@guesses_per_service[this_service] ||= 1
			@@credentials_tried[fq_user] = p
			if counters_expired? this_service,credentials
				break
			else
				@@guesses_per_service[this_service] += 1
			end

		end
	end

	def counters_expired?(this_service,credentials)
		expired_cred = false
		expired_time = false
		# Workaround for cases where multiple auth_brute modules are running concurrently and
		# someone stomps on the @max_per_service class variable during setup.
		current_max_per_service = self.class.class_variable_get("@@max_per_service") rescue nil
		return false unless current_max_per_service
		if @@guesses_per_service[this_service] >= (@@max_per_service)
			if @@max_per_service < credentials.size
				print_brute(
					:level => :vstatus,
					:ip => datastore['RHOST'],
					:port => datastore['RPORT'],
					:msg => "Hit maximum guesses for this service (#{@@max_per_service}).")
					expired_cred = true
			end
		end
		seconds_to_run = datastore['MaxMinutesPerService'].to_i.abs * 60
		if seconds_to_run > 0
			if Time.now.utc.to_i > @@brute_start_time.to_i + seconds_to_run
				print_brute(
					:level => :vstatus,
					:ip => datastore['RHOST'],
					:port => datastore['RPORT'],
					:msg => "Hit timeout for this service at #{seconds_to_run / 60}m.")
					expired_time = true
			end
		end
		expired_cred || expired_time
	end

	# If the user passed a memory location for credential gen, assume
	# that that's precisely what's desired -- no other transforms or
	# additions or uniqueness should be done. Otherwise, perform
	# the usual alterations.
	def build_credentials_array
		credentials = extract_word_pair(datastore['USERPASS_FILE'])
		translate_proto_datastores()
		return credentials if datastore['USERPASS_FILE'] =~ /^memory:/
		users = load_user_vars(credentials)
		passwords = load_password_vars(credentials)
		cleanup_files()
		if datastore['USER_AS_PASS']
			credentials = gen_user_as_password(users, credentials)
		end
		if datastore['BLANK_PASSWORDS']
			credentials = gen_blank_passwords(users, credentials)
		end
		if framework.db.active
			if datastore['DB_ALL_CREDS']
				myworkspace.creds.each do |o|
					credentials << [o.user, o.pass] if o.ptype =~ /password/
				end
			end
			if datastore['DB_ALL_USERS']
				myworkspace.creds.each do |o|
					users << o.user
				end
			end
			if datastore['DB_ALL_PASS']
				myworkspace.creds.each do |o|
					passwords << o.pass if o.ptype =~ /password/
				end
			end
		end
		credentials.concat(combine_users_and_passwords(users, passwords))
		credentials.uniq!
		credentials = just_uniq_users(credentials) if @strip_passwords
		credentials = just_uniq_passwords(credentials) if @strip_usernames
		return credentials
	end

	# Class variables to track credential use. They need
	# to be class variables due to threading.
	def initialize_class_variables(this_service,credentials)
		@@guesses_per_service ||= {}
		@@guesses_per_service[this_service] = nil
		@@credentials_skipped = {}
		@@credentials_tried   = {}
		@@guesses_per_service = {}

		if datastore['MaxGuessesPerService'].to_i.abs == 0
			@@max_per_service = credentials.size
		else
			if datastore['MaxGuessesPerService'].to_i.abs >= credentials.size
				@@max_per_service = credentials.size
				print_brute(
					:level => :vstatus,
					:ip => datastore['RHOST'],
					:port => datastore['RPORT'],
					:msg => "Adjusting MaxGuessesPerService to the actual total number of credentials")
			else
				@@max_per_service = datastore['MaxGuessesPerService'].to_i.abs
			end
		end
		unless datastore['MaxMinutesPerService'].to_i.abs == 0
			@@brute_start_time = Time.now.utc
		end
	end

	def load_user_vars(credentials = nil)
		users = extract_words(datastore['USER_FILE'])
		if datastore['USERNAME']
			users.unshift datastore['USERNAME']
			credentials = prepend_chosen_username(datastore['USERNAME'], credentials) if credentials
		end
		users
	end

	def load_password_vars(credentials = nil)
		passwords = extract_words(datastore['PASS_FILE'])
		if datastore['PASSWORD']
			passwords.unshift datastore['PASSWORD']
			credentials = prepend_chosen_password(datastore['PASSWORD'], credentials) if credentials
		end
		passwords
	end


	# Takes protocol-specific username and password fields, and,
	# if present, prefer those over any given USERNAME or PASSWORD.
	# Note, these special username/passwords should get deprecated
	# some day. Note2: Don't use with SMB and FTP at the same time!
	def translate_proto_datastores
		switched = false
		['SMBUser','FTPUSER'].each do |u|
			if datastore[u] and !datastore[u].empty?
				datastore['USERNAME'] = datastore[u]
			end
		end
		['SMBPass','FTPPASS'].each do |p|
			if datastore[p] and !datastore[p].empty?
				datastore['PASSWORD'] = datastore[p]
			end
		end
	end

	def just_uniq_users(credentials)
		credentials.map {|x| [x[0],""]}.uniq
	end

	def just_uniq_passwords(credentials)
		credentials.map{|x| ["",x[1]]}.uniq
	end

	def prepend_chosen_username(user,cred_array)
		cred_array.map {|pair| [user,pair[1]]} + cred_array
	end

	def prepend_chosen_password(pass,cred_array)
		cred_array.map {|pair| [pair[0],pass]} + cred_array
	end

	def gen_blank_passwords(user_array,cred_array)
		blank_passwords = []
		unless user_array.empty?
			blank_passwords.concat(user_array.map {|u| [u,""]})
		end
		unless cred_array.empty?
			cred_array.each {|u,p| blank_passwords << [u,""]}
		end
		return(blank_passwords + cred_array)
	end

	def gen_user_as_password(user_array,cred_array)
		user_as_passwords = []
		unless user_array.empty?
			user_as_passwords.concat(user_array.map {|u| [u,u]})
		end
		unless cred_array.empty?
			cred_array.each {|u,p| user_as_passwords << [u,u]}
		end
		return(user_as_passwords + cred_array)
	end

	def combine_users_and_passwords(user_array,pass_array)
		if (user_array.length + pass_array.length) < 1
			return []
		end
		combined_array = []
		if pass_array.empty?
			combined_array = user_array.map {|u| [u,""] }
		elsif user_array.empty?
			combined_array = pass_array.map {|p| ["",p] }
		else
			user_array.each do |u|
				pass_array.each do |p|
					combined_array << [u,p]
				end
			end
		end

		creds = [ [], [], [], [] ] # userpass, pass, user, rest
		# Move datastore['USERNAME'] and datastore['PASSWORD'] to the front of the list.
		# Note that we cannot tell the user intention if USERNAME or PASSWORD is blank --
		# maybe (and it's often) they wanted a blank. One more credential won't kill
		# anyone, and hey, won't they be lucky if blank user/blank pass actually works!
		combined_array.each do |pair|
			if pair == [datastore['USERNAME'],datastore['PASSWORD']]
				creds[0] << pair
			elsif pair[1] == datastore['PASSWORD']
				creds[1] << pair
			elsif pair[0] == datastore['USERNAME']
				creds[2] << pair
			else
				creds[3] << pair
			end
		end
		return creds[0] + creds[1] + creds[2] + creds[3]
	end

	def extract_words(wordfile)
		return [] unless wordfile && File.readable?(wordfile)
		begin
			words = File.open(wordfile) {|f| f.read(f.stat.size)}
		rescue
			return
		end
		save_array = words.split(/\r?\n/)
		return save_array
	end

	def get_object_from_memory_location(memloc)
		if memloc.to_s =~ /^memory:\s*([0-9]+)/
			id = $1
			ObjectSpace._id2ref(id.to_s.to_i)
		end
	end

	def extract_word_pair(wordfile)
		creds = []
		if wordfile.to_s =~ /^memory:/
			return extract_word_pair_from_memory(wordfile.to_s)
		else
			return [] unless wordfile && File.readable?(wordfile)
			begin
				upfile_contents = File.open(wordfile) {|f| f.read(f.stat.size)}
			rescue
				return []
			end
			upfile_contents.split(/\n/).each do |line|
				user,pass = line.split(/\s+/,2).map { |x| x.strip }
				creds << [user.to_s, pass.to_s]
			end
			return creds
		end
	end

	def extract_word_pair_from_memory(memloc)
		begin
			creds = []
			obj = get_object_from_memory_location(memloc)
			unless obj.all_creds.empty?
				these_creds = obj.all_creds
			else
				these_creds = obj.builders.select {|x| x.respond_to? :imported_users}.map {|b| b.imported_users}.flatten
			end
			these_creds.each do |cred|
				if @strip_passwords
					user = cred.split(/\s+/,2).map {|x| x.strip}[0]
					pass = ""
				elsif @strip_usernames
					user = ""
					pass = cred.split(/\s+/,2).map {|x| x.strip}[1]
				else
					user,pass = cred.split(/\s+/,2).map {|x| x.strip}
				end
				creds << [Rex::Text.dehex(user.to_s), Rex::Text.dehex(pass.to_s)]
			end
			if @strip_passwords || @strip_usernames
				return creds.uniq
			else
				return creds
			end
		rescue => e
			raise ArgumentError, "Could not read credentials from memory, raised: #{e.class}: #{e.message}"
		end
	end

	def userpass_sleep_interval
		sleep_time = case datastore['BRUTEFORCE_SPEED'].to_i
			when 0; 60 * 5
			when 1; 15
			when 2; 1
			when 3; 0.5
			when 4; 0.1
			else; 0
		end
		::IO.select(nil,nil,nil,sleep_time) unless sleep_time == 0
	end

	# Provides a consistant way to display messages about AuthBrute-mixed modules.
	# Acceptable opts are fairly self-explanitory, but :level can be tricky.
	#
	# It can be one of status, good, error, or line (and corresponds to the usual
	# print_status, print_good, etc. methods).
	#
	# If it's preceded by a "v" (ie, vgood, verror, etc), only print if
	# datastore["VERBOSE"] is set to true.
	#
	# If :level would make the method nonsense, default to print_status.
	#
	# TODO: This needs to be simpler to be useful.
	def print_brute(opts={})
		if opts[:level] and opts[:level].to_s[/^v/]
			return unless datastore["VERBOSE"]
			level = opts[:level].to_s[1,16].strip
		else
			level = opts[:level].to_s.strip
		end

		host_ip = opts[:ip] || opts[:rhost] || opts[:host] || (rhost rescue nil) || datastore['RHOST']
		host_port = opts[:port] || opts[:rport] || (rport rescue nil) || datastore['RPORT']
		msg = opts[:msg] || opts[:message] || opts[:legacy_msg]
		proto = opts[:proto] || opts[:protocol] || proto_from_fullname

		complete_message = build_brute_message(host_ip,host_port,proto,msg,!!opts[:legacy_msg])

		print_method = "print_#{level}"
		if self.respond_to? print_method
			self.send print_method, complete_message
		else
			print_status complete_message
		end
	end

	# Depending on the non-nil elements, build up a standardized
	# auth_brute message, but support the old style used by
	# vprint_status and friends as well.
	def build_brute_message(host_ip,host_port,proto,msg,legacy)
		ip = host_ip.to_s.strip if host_ip
		port = host_port.to_s.strip if host_port
		complete_message = nil
		extracted_message = nil
		if legacy # TODO: This is all a workaround until I get a chance to get rid of the legacy messages
			old_msg = msg.to_s.strip
			msg_regex = /(#{ip})(:#{port})?(\s*-?\s*)(#{proto.to_s})?(\s*-?\s*)(.*)/ni
			if old_msg.match(msg_regex) and !old_msg.match(msg_regex)[6].to_s.strip.empty?
				complete_message = [ip,port].join(":")
				(complete_message << " ") if ip
				complete_message << (old_msg.match(msg_regex)[4] || proto).to_s
				complete_message << " - "
				progress = tried_over_total(ip,port)
				complete_message << progress if progress
				complete_message << old_msg.match(msg_regex)[6].to_s.strip
			else
				complete_message = msg.to_s.strip
			end
		else
			complete_message = [ip,port].join(":")
			(complete_message << " ") if ip
			complete_message << "#{proto.to_s.strip} - " if proto
			progress = tried_over_total(ip,port)
			complete_message << progress if progress
			complete_message << msg.to_s.strip
		end
	end

	# Takes a credentials array, and returns just the first X involving
	# a particular user.
	def adjust_credentials_by_max_user(credentials)
		max = datastore['MaxGuessesPerUser'].to_i.abs
		if max == 0
			new_credentials = credentials
		else
			print_brute(
				:level => :vstatus,
				:msg => "Adjusting credentials by MaxGuessesPerUser (#{max})"
			)
			user_count = {}
			new_credentials = []
			credentials.each do |u,p|
				user_count[u] ||= 0
				user_count[u] += 1
				next if user_count[u] > max
				new_credentials << [u,p]
			end
		end
		return new_credentials
	end

	# Fun trick: Only prints if we're already in each_user_pass, since
	# only then is @@max_per_service defined.
	def tried_over_total(ip,port)
		total = self.class.class_variable_get("@@max_per_service") rescue nil
		return unless total
		total = total.to_i
		current_try = (@@guesses_per_service["#{ip}:#{port}"] || 1).to_i
		pad = total.to_s.size
		"[%0#{pad}d/%0#{pad}d] - " % [current_try, total]
	end

	# Protocols can nearly always be automatically determined from the
	# name of the module, assuming the name is sensible like ssh_login or
	# smb_auth.
	def proto_from_fullname
		File.split(self.fullname).last.match(/^(.*)_(login|auth|identify)/)[1].upcase rescue nil
	end

	# Legacy vprint
	def vprint_status(msg='')
		print_brute :level => :vstatus, :legacy_msg => msg
	end

	# Legacy vprint
	def vprint_error(msg='')
		print_brute :level => :verror, :legacy_msg => msg
	end

	# Legacy vprint
	def vprint_good(msg='')
		print_brute :level => :vgood, :legacy_msg => msg
	end

	# This method deletes the dictionary files if requested
	def cleanup_files
		path = datastore['USERPASS_FILE']
		if path and datastore['REMOVE_USERPASS_FILE']
			::File.unlink(path) rescue nil
		end

		path = datastore['USER_FILE']
		if path and datastore['REMOVE_USER_FILE']
			::File.unlink(path) rescue nil
		end

		path = datastore['PASS_FILE']
		if path and datastore['REMOVE_PASS_FILE']
			::File.unlink(path) rescue nil
		end
	end

end
end

