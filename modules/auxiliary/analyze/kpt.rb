##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	def initialize
		super(
			'Name'		=> 'KnownPlainText.co Password Cracker',
			'Description'       => %Q{
				This module uses the KnownPlainText.co service to identify weak passwords
				that have been acquired as hashed files (loot) or raw LANMAN/NTLM hashes 
				(hashdump). The goal of this module is to find trivial passwords in a short 
				amount of time. To crack complex passwords another password cracking tool
				should be used outside of Metasploit.
				You must have a working copy of the KnownPlainText client including a 
				valid license key for this module to work properly.
			},
			'Author'			=> 'averagesecurityguy',
			'License'			=> MSF_LICENSE
		)

		register_options(
			[
				OptPath.new('KPT_PATH', [false, 'The directory containing the KnownPlainText client']),
			], self.class)
	end

	def run

		# Create a PWDUMP style input file for SMB Hashes
		pwdump = ::File.join( datastore["KPT_PATH"], "metasploit.pwdump")
		hashlist = Rex::Quickfile.new(pwdump)
		smb_hashes = myworkspace.creds.select{|x| x.ptype == "smb_hash" }
		smb_hashes.each do |cred|
			hashlist.write( "cred_#{cred[:id]}:#{cred[:id]}:#{cred[:pass]}:::\n" )
		end
		hashlist.close

		# Use KnownPlainText.co to lookup the hashes.
		kpt_exe = ::File.join( datastore["KPT_PATH"], "client.py" )
		cmd = kpt_exe + ' -p ' + hashlist.path
		print_status(cmd)
		::IO.popen(cmd, "rb") do |fd|
			fd.each_line do |line|
				line.chomp!

				# Store the cracked results based on user_id => cred.id
				next if not line =~ /^cred_(\d+):(.*)/m
				cid = $1.to_i
				pass = $2

				cred_find = smb_hashes.select{|x| x[:id] == cid}
				next if cred_find.length == 0
				cred = cred_find.first
				next if cred.user.to_s.strip.length == 0

				print_good("Cracked: #{cred.user}:#{pass} (#{cred.service.host.address}:#{cred.service.port})")
				report_auth_info(
					:host  => cred.service.host,
					:service => cred.service,
					:user  => cred.user,
					:pass  => pass,
					:type  => "password",
					:source_id   => cred[:id],
					:source_type => 'cracked'
				)
			end
		end
	end
end
