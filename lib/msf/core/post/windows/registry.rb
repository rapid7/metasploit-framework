# -*- coding: binary -*-

require 'msf/core/post/windows/cli_parse'

module Msf
class Post
module Windows

module Registry

	include Msf::Post::Windows::CliParse

	#
	# Load a hive file
	#
	def registry_loadkey(key,file)
		if session_has_registry_ext
			retval=meterpreter_registry_loadkey(key,file)
		else
			retval=shell_registry_loadkey(key,file)
		end
		return retval
	end

	#
	# Unload a hive file
	#
	def registry_unloadkey(key)
		if session_has_registry_ext
			retval=meterpreter_registry_unloadkey(key)
		else
			retval=shell_registry_unloadkey(key)
		end
		return retval
	end

	#
	# Create the given registry key
	#
	def registry_createkey(key)
		if session_has_registry_ext
			meterpreter_registry_createkey(key)
		else
			shell_registry_createkey(key)
		end
	end

	#
	# Deletes a registry value given the key and value name
	#
	# returns true if succesful
	#
	def registry_deleteval(key, valname)
		if session_has_registry_ext
			meterpreter_registry_deleteval(key, valname)
		else
			shell_registry_deleteval(key, valname)
		end
	end

	#
	# Delete a given registry key
	#
	# returns true if succesful
	#
	def registry_deletekey(key)
		if session_has_registry_ext
			meterpreter_registry_deletekey(key)
		else
			shell_registry_deletekey(key)
		end
	end

	#
	# Return an array of subkeys for the given registry key
	#
	def registry_enumkeys(key)
		if session_has_registry_ext
			meterpreter_registry_enumkeys(key)
		else
			shell_registry_enumkeys(key)
		end
	end

	#
	# Return an array of value names for the given registry key
	#
	def registry_enumvals(key)
		if session_has_registry_ext
			meterpreter_registry_enumvals(key)
		else
			shell_registry_enumvals(key)
		end
	end

	#
	# Return the data of a given registry key and value
	#
	def registry_getvaldata(key, valname)
		if session_has_registry_ext
			meterpreter_registry_getvaldata(key, valname)
		else
			shell_registry_getvaldata(key, valname)
		end
	end

	#
	# Return the data and type of a given registry key and value
	#
	def registry_getvalinfo(key,valname)
		if session_has_registry_ext
			meterpreter_registry_getvalinfo(key, valname)
		else
			shell_registry_getvalinfo(key, valname)
		end
	end

	#
	# Sets the data for a given value and type of data on the target registry
	#
	# returns true if succesful
	#
	def registry_setvaldata(key, valname, data, type)
		if session_has_registry_ext
			meterpreter_registry_setvaldata(key, valname, data, type)
		else
			shell_registry_setvaldata(key, valname, data, type)
		end
	end

protected

	#
	# Determines whether the session can use meterpreter registry methods
	#
	def session_has_registry_ext
		begin
			return !!(session.sys and session.sys.registry)
		rescue NoMethodError
			return false
		end
	end


	##
	# Generic registry manipulation methods based on reg.exe
	##

	#
	# Use reg.exe to load the hive file +file+ into +key+
	#
	def shell_registry_loadkey(key,file)
		key = normalize_key(key)
		boo = false
		file = "\"#{file}\""
		cmd = "cmd.exe /c reg load #{key} #{file}"
		results = session.shell_command_token_win32(cmd)
		if results =~ /The operation completed successfully/
			boo = true
		elsif results =~ /^Error:/
			error_hash = win_parse_error(results)
		else
			error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
		end
		return boo
	end

	#
	# Use reg.exe to unload the hive in +key+
	#
	def shell_registry_unloadkey(key)
		key = normalize_key(key)
		boo = false
		cmd = "cmd.exe /c reg unload #{key}"
		results = session.shell_command_token_win32(cmd)
		if results =~ /The operation completed successfully/
			boo = true
		elsif results =~ /^Error:/
			error_hash = win_parse_error(results)
		else
			error_hash = win_parse_error("ERROR:Unknown error running #{cmd} INSPECT: #{error_hash.inspect}")
		end
		return boo
	end


	#
	# Use reg.exe to create a new registry key
	#
	def shell_registry_createkey(key)
		key = normalize_key(key)
		boo = false
		begin
			# REG ADD KeyName [/v ValueName | /ve] [/t Type] [/s Separator] [/d Data] [/f]
			cmd = "cmd.exe /c reg add \"#{key}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				boo = true
			elsif results =~ /^Error:/
				error_hash = win_parse_error(results)
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
	end

	#
	# Use reg.exe to delete +valname+ in +key+
	#
	def shell_registry_deleteval(key, valname)
		key = normalize_key(key)
		boo = false
		begin
			# REG DELETE KeyName [/v ValueName | /ve | /va] [/f]
			cmd = "cmd.exe /c reg delete \"#{key}\" /v \"#{valname}\" /f"
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				boo = true
			elsif results =~ /^Error:/
				error_hash = win_parse_error(results)
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
		return boo
	end

	#
	# Use reg.exe to delete +key+ and all its subkeys and values
	#
	def shell_registry_deletekey(key)
		key = normalize_key(key)
		boo = false
		begin
			# REG DELETE KeyName [/v ValueName | /ve | /va] [/f]
			cmd = "cmd.exe /c reg delete \"#{key}\" /f"
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				boo = true
			elsif results =~ /^Error:/
				error_hash = win_parse_error(results)
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
		return boo
	end

	#
	# Use reg.exe to enumerate all the subkeys in +key+
	#
	def shell_registry_enumkeys(key)
		key = normalize_key(key)
		subkeys = []
		reg_data_types = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|'
		reg_data_types << 'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR'
		begin
			bslashes = key.count('\\')
			cmd = "cmd.exe /c reg query \"#{key}\""
			results = session.shell_command_token_win32(cmd)
			if results
				if results =~ /^Error:/
					error_hash = win_parse_error(results)
				else # would like to use elsif results =~ /#{key}/  but can't figure it out
					results.each_line do |line|
						# now let's keep the ones that have a count = bslashes+1
						# feels like there's a smarter way to do this but...
						if (line.count('\\') == bslashes+1 && !line.ends_with?('\\'))
							#then it's a first level subkey
							subkeys << line.split('\\').last.chomp # take & chomp the last item only
						end
					end
				#else
				#	error_hash = win_parse_error("ERROR:Unrecognizable results from #{cmd}")
				end
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
		return subkeys
	end

	#
	# Use reg.exe to enumerate all the values in +key+
	#
	def shell_registry_enumvals(key)
		key = normalize_key(key)
		values = []
		reg_data_types = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|'
		reg_data_types << 'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR'
		begin
			# REG QUERY KeyName [/v ValueName | /ve] [/s]
			cmd = "cmd.exe /c reg query \"#{key}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ /^Error:/
				error_hash = win_parse_error(results)
			elsif values = results.scan(/^ +.*[#{reg_data_types}].*/)
				# yanked the lines with legit REG value types like REG_SZ
				# now let's parse out the names (first field basically)
				values.collect! do |line|
					t = line.split(' ')[0].chomp #chomp for good measure
					# check if reg returned "<NO NAME>", which splits to "<NO", if so nil instead
					t = nil if t == "<NO"
					t
				end
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
		return values
	end

	#
	# Returns the data portion of the value +valname+
	#
	def shell_registry_getvaldata(key, valname)
		value = nil
		begin
			a = shell_registry_getvalinfo(key, valname)
			value = a["Data"] || nil
		end
		return value
	end

	#
	# Enumerate the type and data stored in the registry value +valname+ in
	# +key+
	#
	def shell_registry_getvalinfo(key, valname)
		key = normalize_key(key)
		value = {}
		value["Data"] = nil # defaults
		value["Type"] = nil
		begin
			# REG QUERY KeyName [/v ValueName | /ve] [/s]
			cmd = "cmd.exe /c reg query \"#{key}\" /v \"#{valname}\""
			results = session.shell_command_token_win32(cmd)
			if match_arr = /^ +#{valname}.*/i.match(results)
				# pull out the interesting line (the one with the value name in it)
				# and split it with ' ' yielding [valname,REGvaltype,REGdata]
				split_arr = match_arr[0].split(' ')
				value["Type"] = split_arr[1]
				value["Data"] = split_arr[2]
				# need to test to ensure all results can be parsed this way
			elsif results =~ /^Error:/
				error_hash = win_parse_error(results)
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
		return value
	end

	#
	# Use reg.exe to add a value +valname+ in the key +key+ with the specified
	# +type+ and +data+
	#
	def shell_registry_setvaldata(key, valname, data, type)
		key = normalize_key(key)
		boo = false
		begin
			# REG ADD KeyName [/v ValueName | /ve] [/t Type] [/s Separator] [/d Data] [/f]
			# /f to overwrite w/o prompt
			cmd = "cmd.exe /c reg add \"#{key}\" /v \"#{valname}\" /t \"#{type}\" /d \"#{data}\" /f"
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				boo = true
			elsif results =~ /^Error:/
				error_hash = win_parse_error(results)
			else
				error_hash = win_parse_error("ERROR:Unknown error running #{cmd}")
			end
		end
		return boo
	end


	##
	# Meterpreter-specific registry manipulation methods
	##

	#
	# Load a registry hive stored in +file+ into +key+
	#
	def meterpreter_registry_loadkey(key,file)
		begin
			client.sys.config.getprivs()
			root_key, base_key = session.sys.registry.splitkey(key)
			#print_debug("Loading file #{file}")
			begin
				loadres= session.sys.registry.load_key(root_key,base_key,file)
			rescue Rex::Post::Meterpreter::RequestError => e
				case e.to_s
				when "stdapi_registry_load_key: Operation failed: 1314"
					#print_error("You appear to be lacking the SeRestorePrivilege. Are you running with Admin privs?")
					return false
				when "stdapi_registry_load_key: Operation failed: The system cannot find the path specified."
					#print_error("The path you provided to the Registry Hive does not Appear to be valid: #{file}")
					return false
				when "stdapi_registry_load_key: Operation failed: The process cannot access the file because it is being used by another process."
					#print_error("The file you specified is currently locked by another process: #{file}")
					return false
				when /stdapi_registry_load_key: Operation failed:/
					#print_error("An unknown error has occured: #{loadres.to_s}")
					return false
				else
					#print_debug("Registry Hive Loaded Successfully: #{key}")
					return true
				end
			end

		rescue
			return false
		end

	end

	#
	# Unload the hive file stored in +key+
	#
	def meterpreter_registry_unloadkey(key)
		begin
			client.sys.config.getprivs()
			root_key, base_key = session.sys.registry.splitkey(key)
			begin
				unloadres= session.sys.registry.unload_key(root_key,base_key)
			rescue Rex::Post::Meterpreter::RequestError => e
				case e.to_s
				when "stdapi_registry_unload_key: Operation failed: The parameter is incorrect."
					#print_error("The KEY you provided does not appear to match a loaded Registry Hive: #{key}")
					return false
				when /stdapi_registry_unload_key: Operation failed:/
					#print_error("An unknown error has occured: #{unloadres.to_s}")
					return false
				else
					#print_debug("Registry Hive Unloaded Successfully: #{key}")
					return true
				end
			end
		rescue
			return false
		end
	end

	#
	# Create a new registry key
	#
	def meterpreter_registry_createkey(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)

			open_key = session.sys.registry.create_key(root_key, base_key)
			open_key.close
			return true
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
	end

	#
	# Delete the registry value +valname+ store in +key+
	#
	def meterpreter_registry_deleteval(key, valname)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
			open_key.delete_value(valname)
			open_key.close
			return true
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
	end

	#
	# Delete the registry key +key+
	#
	def meterpreter_registry_deletekey(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			deleted = session.sys.registry.delete_key(root_key, base_key)
			return deleted
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
	end

	#
	# Enumerate the subkeys in +key+
	#
	def meterpreter_registry_enumkeys(key)
		subkeys = []
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			keys = open_key.enum_key
			keys.each { |subkey|
				subkeys << subkey
			}
			open_key.close
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
		return subkeys
	end

	#
	# Enumerate the values in +key+
	#
	def meterpreter_registry_enumvals(key)
		values = []
		begin
			vals = {}
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			vals = open_key.enum_value
			vals.each { |val|
				values <<  val.name
			}
			open_key.close
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
		return values
	end

	#
	# Get the data stored in the value +valname+
	#
	def meterpreter_registry_getvaldata(key, valname)
		value = nil
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value = v.data
			open_key.close
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
		return value
	end

	#
	# Enumerate the type and data of the value +valname+
	#
	def meterpreter_registry_getvalinfo(key, valname)
		value = {}
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value["Data"] = v.data
			value["Type"] = v.type
			open_key.close
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
		return value
	end

	#
	# Add the value +valname+ to the key +key+ with the specified +type+ and +data+
	#
	def meterpreter_registry_setvaldata(key, valname, data, type)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
			open_key.set_value(valname, session.sys.registry.type2str(type), data)
			open_key.close
			return true
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
	end

	#
	# Normalize the supplied full registry key string so the root key is sane.  For
	# instance, passing "HKLM\Software\Dog" will return 'HKEY_LOCAL_MACHINE\Software\Dog'
	#
	def normalize_key(key)
		keys = split_key(key)
		if (keys[0] =~ /HKLM|HKEY_LOCAL_MACHINE/)
			keys[0] = 'HKEY_LOCAL_MACHINE'
		elsif (keys[0] =~ /HKCU|HKEY_CURRENT_USER/)
			keys[0] = 'HKEY_CURRENT_USER'
		elsif (keys[0] =~ /HKU|HKEY_USERS/)
			keys[0] = 'HKEY_USERS'
		elsif (keys[0] =~ /HKCR|HKEY_CLASSES_ROOT/)
			keys[0] = 'HKEY_CLASSES_ROOT'
		elsif (keys[0] =~ /HKCC|HKEY_CURRENT_CONFIG/)
			keys[0] = 'HKEY_CURRENT_CONFIG'
		elsif (keys[0] =~ /HKPD|HKEY_PERFORMANCE_DATA/)
			keys[0] = 'HKEY_PERFORMANCE_DATA'
		elsif (keys[0] =~ /HKDD|HKEY_DYN_DATA/)
			keys[0] = 'HKEY_DYN_DATA'
		else
			raise ArgumentError, "Cannot normalize unknown key: #{key}"
		end
		print_status("Normalized #{key} to #{keys.join("\\")}") if $blab
		return keys.join("\\")
	end

	#
	# Split the supplied full registry key string into its root key and base key.  For
	# instance, passing "HKLM\Software\Dog" will return [ 'HKEY_LOCAL_MACHINE',
	# 'Software\Dog' ]
	#
	def split_key(str)
		if (str =~ /^(.+?)\\(.*)$/)
			[ $1, $2 ]
		else
			[ str, nil ]
		end
	end

end
end
end
end
