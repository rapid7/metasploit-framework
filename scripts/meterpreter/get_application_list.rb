# $Id$
# Meterpreter script for listing installed applications and their version.
# Provided: carlos_perez[at]darkoperator[dot]com

#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
        "-h" => [ false, "Help menu." ]
)

def app_list
	tbl = Rex::Ui::Text::Table.new(
		'Header'  => "Installed Applications",
		'Indent'  => 1,
		'Columns' =>
		  [
			"Name",
			"Version"
		])
	appkeys = ['HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
		'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' ]
	appkeys.each do |keyx86|
	
		registry_enumkeys(keyx86).each do |k|
			begin
				dispnm = registry_getvaldata("#{keyx86}\\#{k}","DisplayName")
				dispversion = registry_getvaldata("#{keyx86}\\#{k}","DisplayVersion")
				tbl << [dispnm,dispversion]
			rescue
			end
		end
				
	
	end
	print("\n" + tbl.to_s + "\n")
end

opts.parse(args) { |opt, idx, val|
        case opt
        when "-h"
                print_line "Meterpreter Script for extracting a list installed applications and their version."
                print_line(opts.usage)
                raise Rex::Script::Completed

        end
}
if client.platform =~ /win32|win64/
	app_list
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end