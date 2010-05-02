module Msf
module Scripts
module Meterpreter
module Common

#
# Commonly used methods and techniques for Meterpreter scripts
#

#
# These methods should only print output in the case of an error. All code should be tab indented
# All methods should follow the naming coventions below (separate words with "_", end queries with a ?, etc)
#

def is_uac_enabled?
	uac = false
	winversion = client.sys.config.sysinfo

	if winversion['OS']=~ /Windows Vista/ or  winversion['OS']=~ /Windows 7/
		if client.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
			begin
				key = client.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')

				if key.query_value('Identifier') == 1
					uac = true
				end

				key.close
			rescue::Exception => e
				print_error("Error Checking UAC: #{e.class} #{e}")
			end
		end
	end
    return uac
end


end
end
end
end

