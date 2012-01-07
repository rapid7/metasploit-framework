##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SSH Public Key Acceptance Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module can determine what public keys are configured for
				key-based authentication across a range of machines, users, and
				sets of known keys. The SSH protocol indicates whether a particular
				key is accepted prior to the client performing the actual signed
				authentication request. To use this module, a text file containing
				one or more SSH keys should be provided. These can be private or
				public, so long as no passphrase is set on the private keys.
								
				If you have loaded a database plugin and connected to a database
				this module will record authorized public keys and hosts so you can
				track your process.


				Key files may be a single public (unencrypted) key, or several public
				keys concatenated together as an ASCII text file. Non-key data should be
				silently ignored. Private keys will only utilize the public key component
				stored within the key file.
			},
			'Author'      => ['todb', 'hdm'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(22),
				OptPath.new('KEY_FILE', [false, 'Filename of one or several cleartext public keys.'])
			], self.class
		)

		register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
				OptString.new('SSH_KEYFILE_B64', [false, 'Raw data of an unencrypted SSH public key. This should be used by programmatic interfaces to this module only.', '']),
				OptPath.new('KEY_DIR', [false, 'Directory of several keys. Filenames must not begin with a dot in order to be read.'])
			]
		)

		deregister_options('RHOST','PASSWORD','PASS_FILE','BLANK_PASSWORDS','USER_AS_PASS')

		@good_credentials = {}
		@good_key = ''
		@strip_passwords = true

	end

	def key_dir
		datastore['KEY_DIR']
	end

	def rport
		datastore['RPORT']
	end

	def ip
		datastore['RHOST']
	end

	def read_keyfile(file)
		if file == :keyfile_b64
			keyfile = datastore['SSH_KEYFILE_B64'].unpack("m*").first
		elsif file.kind_of? Array
			keyfile = ''
			file.each do |dir_entry|
				next unless ::File.readable? dir_entry
				keyfile << ::File.open(dir_entry, "rb") {|f| f.read(f.stat.size)}
			end
		else
			keyfile = ::File.open(file, "rb") {|f| f.read(f.stat.size)}
		end
		keys = []
		this_key = []
		in_key = false
		keyfile.split("\n").each do |line|
			if line =~ /ssh-(dss|rsa)\s+/
				keys << line
				next
			end
		
			in_key = true if(line =~ /^-----BEGIN [RD]SA (PRIVATE|PUBLIC) KEY-----/)
			this_key << line if in_key
			if(line =~ /^-----END [RD]SA (PRIVATE|PUBLIC) KEY-----/)
				in_key = false
				keys << (this_key.join("\n") + "\n")
				this_key = []
			end
		end
		if keys.empty?
			print_error "#{ip}:#{rport} SSH - No valid keys found"
		end
		return validate_keys(keys)
	end

	# Validates that the key isn't total garbage. Also throws out SSH2 keys --
	# can't use 'em for Net::SSH.
	def validate_keys(keys)
		keepers = []
		keys.each do |key|
			if key =~ /ssh-(dss|rsa)/
				keepers << key
				next
			end
			
			# Needs a beginning
			next unless key =~ /^-----BEGIN [RD]SA (PRIVATE|PUBLIC) KEY-----\x0d?\x0a/m
			# Needs an end
			next unless key =~ /\n-----END [RD]SA (PRIVATE|PUBLIC) KEY-----\x0d?\x0a?$/m
			# Shouldn't have binary.
			next unless key.scan(/[\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff]/).empty?
			# Add more tests to taste.
			keepers << key
		end
		if keepers.empty?
			print_error "#{ip}:#{rport} SSH - No valid keys found"
		end
		return keepers.uniq
	end

	def pull_cleartext_keys(keys)
		cleartext_keys = []
		keys.each do |key|
			next unless key
			next if key =~ /Proc-Type:.*ENCRYPTED/
			this_key = key.gsub(/\x0d/,"")
			next if cleartext_keys.include? this_key
			cleartext_keys << this_key
		end
		if cleartext_keys.empty?
			print_error "#{ip}:#{rport} SSH - No valid cleartext keys found"
		end
		return cleartext_keys
	end

	def do_login(ip, port, user)

		if datastore['KEY_FILE'] and File.readable?(datastore['KEY_FILE'])
			keys = read_keyfile(datastore['KEY_FILE'])
			@keyfile_path = datastore['KEY_FILE'].dup
			cleartext_keys = pull_cleartext_keys(keys)
			msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user."
		elsif datastore['SSH_KEYFILE_B64'] && !datastore['SSH_KEYFILE_B64'].empty?
			keys = read_keyfile(:keyfile_b64)
			cleartext_keys = pull_cleartext_keys(keys)
			msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user (read from datastore)."
		elsif datastore['KEY_DIR']
			@keyfile_path = datastore['KEY_DIR'].dup
			return :missing_keyfile unless(File.directory?(key_dir) && File.readable?(key_dir))
			unless @key_files
				@key_files = Dir.entries(key_dir).reject {|f| f =~ /^\x2e/ || f =~ /\x2epub$/}
			end
			these_keys = @key_files.map {|f| File.join(key_dir,f)}
			keys = read_keyfile(these_keys)
			cleartext_keys = pull_cleartext_keys(keys)
			msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user."
		else
			return :missing_keyfile
		end
		
		unless @alerted_with_msg
			print_status msg
			@alerted_with_msg = true
		end
		
		cleartext_keys.each_with_index do |key_data,key_idx|
			key_info  = ""
			
			if key_data =~ /ssh\-(rsa|dsa)\s+([^\s]+)\s+(.*)/
				key_info = "- #{$3.strip}"
			end
			
			
			accepted = []
			opt_hash = {
				:auth_methods => ['publickey'],
				:msframework  => framework,
				:msfmodule    => self,
				:port         => port,
				:key_data     => key_data,
				:disable_agent     => true,
				:record_auth_info  => true,
				:skip_private_keys => true,
				:accepted_key_callback => Proc.new {|key| accepted << key }
			}
			
			opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']
			
			begin
				ssh_socket = Net::SSH.start(ip, user, opt_hash)
				ssh_socket.close rescue nil
				
			rescue Rex::ConnectionError, Rex::AddressInUse
				return :connection_error
			rescue Net::SSH::Disconnect, ::EOFError
				return :connection_disconnect
			rescue Net::SSH::AuthenticationFailed
			rescue Net::SSH::Exception => e
				return [:fail,nil] # For whatever reason.
			end
			
			if accepted.length == 0
				if @key_files
					vprint_error "#{ip}:#{rport} - SSH - User #{user} does not accept key #{@key_files[key_idx+1]} #{key_info}"
				else
					vprint_error "#{ip}:#{rport} - SSH - User #{user} does not accept key #{key_idx+1} #{key_info}"
				end
			end
			
			accepted.each do |key|
				print_good "#{ip}:#{rport} SSH - Accepted: '#{user}' with key '#{key[:fingerprint]}' #{key_info}"
				do_report(ip, rport, user, key)
			end
		end
	end

	def do_report(ip, port, user, key)
		report_note(
			:host     => ip, 
			:type     => 'ssh.authorized_key', 
			:port     => port, 
			:protocol => 'tcp', 
			:data     => {:username => user, :fingerprint => key[:fingerprint] },
			:insert   => :unique_data
		)
	end		
		

	def run_host(ip) 
		# Since SSH collects keys and tries them all on one authentication session, it doesn't
		# make sense to iteratively go through all the keys individually. So, ignore the pass variable,
		# and try all available keys for all users.
		each_user_pass do |user,pass|
			ret, proof = do_login(ip, rport, user)
			case ret
			when :connection_error
				vprint_error "#{ip}:#{rport} - SSH - Could not connect"
				:abort
			when :connection_disconnect
				vprint_error "#{ip}:#{rport} - SSH - Connection timed out"
				:abort
			when :fail
				vprint_error "#{ip}:#{rport} - SSH - Failed: '#{user}'"
			when :missing_keyfile
				vprint_error "#{ip}:#{rport} - SSH - Cannot read keyfile"
			when :no_valid_keys
				vprint_error "#{ip}:#{rport} - SSH - No readable keys in keyfile"
			end
		end
	end

end

