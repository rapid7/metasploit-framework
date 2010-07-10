# $Id$
# $Revision$
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

#-------------------------------------------------------------------------------

######################## Functions ########################
def ls_logged
	sids = []
	sids << registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
	tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Logged Users",
			'Indent'  => 1,
			'Columns' =>
				[
					"SID",
					"Profile Path"
				])
	sids.flatten.each do |sid|
		profile_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{sid}","ProfileImagePath")
		tbl << [sid,profile_path]
	end
	print_line("\n" + tbl.to_s + "\n")
end

def ls_current
	key_base, username = "",""
	tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Current Logged Users",
			'Indent'  => 1,
			'Columns' =>
				[
					"SID",
					"User"
				])
	registry_enumkeys("HKU").each do |sid|
		case sid
		when "S-1-5-18"
			username = "SYSTEM"
			tbl << [sid,username]
		when "S-1-5-19"
			username = "Local Service"
			tbl << [sid,username]
		when "S-1-5-20"
			username = "Network Service"
			tbl << [sid,username]
		else
			if sid =~ /S-1-5-21-\d*-\d*-\d*-\d{4}$/
			key_base = "HKU\\#{sid}" 
			username = registry_getvaldata("#{key_base}\\Volatile Environment","USERNAME")
			tbl << [sid,username]
			end
		end
	end
	print_line("\n" + tbl.to_s + "\n")
end
#-------------------------------------------------------------------------------
####################### Options ###########################
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-l" => [ false, "List SID's of users who have loged in to the host." ],
	"-c" => [ false, "List SID's of currently loged on users." ]
	)
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line "Meterpreter Script for enumerating Current logged users and users that have loged in to the system."
		print_line(@@exec_opts.usage)
		raise Rex::Script::Completed
	when "-l"
		ls_logged
	when "-c"
		ls_current
	end
}
if args.length == 0
	print_line "Meterpreter Script for enumerating Current logged users and users that have loged in to the system."
	print_line(@@exec_opts.usage)
	raise Rex::Script::Completed
end
