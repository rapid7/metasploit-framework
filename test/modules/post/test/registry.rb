
##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'test',
				'Description'   => %q{ This module will test registry stuff },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ]
			))
		register_options(
		[
				OptBool.new("VERBOSE" , [ true, "Enumerate currently configured shares", true]),
				OptString.new("KEY" , [true, "Registry key to test", "HKLM\\Software\\Microsoft\\Active Setup"]),
				OptString.new("VALUE" , [true, "Registry value to test", "DisableRepair"]),
			], self.class)

	end

	def run
		$blab = false
		#$blab = true if datastore["VERBOSE"]
		print_status("Running against session #{datastore["SESSION"]}")

		print_status "testing get_val_info for key:#{datastore['KEY']}, val:#{datastore['VALUE']}"
		results = registry_getvalinfo(datastore['KEY'], datastore['VALUE'])
		print_status ("results: #{results.class} #{results.inspect}")
		print_status "testing get_val_data for key:#{datastore['KEY']}, val:#{datastore['VALUE']}"
		results = registry_getvaldata(datastore['KEY'], datastore['VALUE'])
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "testing create_key for key:#{datastore['KEY']}\\test"
		results = registry_createkey("#{datastore['KEY']}\\test")
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "testing set_val_data for key:#{datastore['KEY']}\\test, val:test, data:test, type:REG_SZ"
		results = registry_setvaldata("#{datastore['KEY']}\\test", "test", "test", "REG_SZ")
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "getting newly created val_info for key:#{datastore['KEY']}\\test, val:test"
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "testing del_val_data for key:#{datastore['KEY']}\\test, val:test"
		results = registry_deleteval("#{datastore['KEY']}\\test", "test")
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "testing del_key"
		results = registry_deletekey("#{datastore['KEY']}\\test")
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "getting deleted val_info for key:#{datastore['KEY']}\\test, val:test, this should return nils"
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "testing enum_keys"
		results = registry_enumkeys(datastore['KEY'])
		print_status ("results: #{results.class} #{results.inspect}")

		print_status "testing enum_vals"
		results = registry_enumvals(datastore['KEY'])
		print_status ("results: #{results.class} #{results.inspect}")

	end

end

module Msf::Post::Registry
	def session_has_registry_ext?; true; end

	#
	# Returns the data and type of a given registry key and value
	#
	def shell_registry_getvalinfo(key, valname)
		key = normalize_key(key)
		value = {}
		value["Data"] = nil # defaults
		value["Type"] = nil
		begin
			# REG QUERY KeyName [/v ValueName | /ve] [/s]
			cmd = "cmd.exe /c reg query \"#{key}\" /v \"#{valname}\""
			print_status "cmd is: #{cmd}" if $blab
			results = session.shell_command_token_win32(cmd)
			print_status "raw results are:\n#{results}" if $blab
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
	# Returns the data of a given registry key and value
	#
	def shell_registry_getvaldata(key, valname)
		value = nil
		begin
			a = self.registry_getvalinfo(key, valname)
			value = a["Data"] || nil
		end
		return value
	end

	#
	# Sets the data for a given value and type of data on the target registry returns true if successful
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

	#
	# Deletes a registry value given the key and value name returns true if successful
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
	# Enumerates the values of a given registry key returns array of value names
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
	# Enumerates the subkeys of a given registry key returns array of subkeys
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

	# Create a given registry key returns true if successful
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

	# Delete a given registry key returns true if successful
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

protected
	#
	# Parses output of some windows CLI commands and returns hash with the keys/vals detected
	# 	if the item has multiple values, they will all be returned in the val separated by commas
	#
	#--- sc.exe example (somewhat contrived)
	# SERVICE_NAME: dumbservice
	# DISPLAY_NAME: KernelSmith Dumb Service - User-mode
	# TYPE               : 20  WIN32_SHARE_PROCESS
	# STATE              : 4  RUNNING
	#                         (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
	# START_TYPE         : 2   AUTO_START
	# BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
	# DEPENDENCIES       : PlugPlay
	#                    : DumberService
	# SERVICE_START_NAME : LocalSystem
	# PID                : 368
	# FLAGS              :
	#--- END sc.exe example
	#
	# Example would return:
	# {
	#  'SERVICE_NAME'     => "dumbservice",
	#  'DISPLAY_NAME'     => "KernelSmith Dumb Service - User-mod",
	#  'STATE'            => "4  RUNNING",
	#  'START_TYPE'       => "2   AUTO_START",
	#  'BINARY_PATH_NAME' => "C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted",
	#  'DEPENDENCIES'     => "PlugPlay,DumberService"
	#  <...etc...>
	# }
	#
	def win_parse_results(str)
		print_status "Parsing results string: #{str}" if $blab
		tip = false
		hashish = Hash.new(nil)
		lastkey = nil
		str.each_line do |line|
			line.chomp! 
			line.gsub!("\t", ' ') # lose any tabs
			if (tip == true && line =~ /^ + :/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this will NOT pickup the (NOT_STOPPABLE, NOT_PAUSABLE), see next, but it
				# 	 will pickup when there's multiple dependencies
				print_status "Caught line continuation with :" if $blab
				arr = line.scan(/\w+/)
				val = arr.join(',') # join with commas, tho there is probably only one item in arr
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif (tip == true && line =~ /^ + \(/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this WILL pickup (NOT_STOPPABLE, NOT_PAUSABLE) etc
				print_status "Caught line continuation with (" if $blab
				arr = line.scan(/\w+/) # put each "word" into an array
				val = arr.join(',') # join back together with commas in case comma wasn't the sep
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false			
			elsif line =~ /^ *[A-Z]+[_]*[A-Z]+.*:/
				tip = true
				arr = line.split(':')
				#print_status "Array split is #{arr.inspect}" if $blab
				k = arr[0].strip
				# grab all remaining fields for hash val in case ':' present in val
				v = arr[1..-1].join(':').strip
				# now add this entry to the hash
				#print_status "Adding the following hash entry: #{k} => #{v}" if $blab
				hashish[k] = v 
				lastkey = k
			end
		end
		return hashish
	end
	
	#
	# parses error output of some windows CLI commands and returns hash with the keys/vals detected
	#  always returns hash as follow but ERRVAL only comes back from sc.exe using 'FAILED' keyword
	#
	# Note, most of the time the ERRVAL will be nil, it's not usually provided
	#
	#--- sc.exe error example
	# [SC] EnumQueryServicesStatus:OpenService FAILED 1060:
	#
	# The specified service does not exist as an installed service.
	#--- END sc.exe error example
	# returns
	# {
	#	:error  => "The specified service does not exist as an installed service",
	#	:errval => 1060
	# }
	#
	#--- reg.exe error example
	# ERROR: Invalid key name.
	# Type "REG QUERY /?" for usage.
	#--- END reg.exe error example
	# returns
	#  {
	#    :error  => "INVALID KEY NAME."
	#    :errval => nil
	#  }
	#
	def win_parse_error(str)
		hashish = {
				:error => "Unknown Error",
				:errval => nil
			  }
		if ma = /^error:.*/i.match(str) # if line starts with Error: just pass to regular parser
			hashish.merge!(win_parse_results(ma[0].upcase)) #upcase required to satisfy regular parser
			# merge results.  Results from win_parse_results will override any duplicates in hashish
		elsif ma = /FAILED +[0-9]+/.match(str) # look for 'FAILED ' followed by some numbers
			print_status "Found FAILED, ma is #{ma.inspect}" if $blab
			sa = ma[0].split(' ')
			print_status "sa is #{sa.inspect}" if $blab
			hashish[:errval] = sa[1].chomp.to_i
			# above intended to capture the numbers after the word 'FAILED' as [:errval]
			ma = /^[^\[\n].+/.match(str)
			print_status "ma is #{ma.inspect}" if $blab
			hashish[:error] = ma[0].chomp.strip
			# above intended to capture first non-empty line not starting with '[' or \n into [:error]
		else
			# do nothing, defaults are good
		end
		print_error "Error hash:  #{hashish.inspect}" if $blab
		print_error "This error hash is optionally available:  #{hashish.pretty_inspect}"
		return hashish
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

