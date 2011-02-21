
module Msf
class Post
module Windows

module CliParse
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
	#	'SERVICE_NAME'     => "dumbservice",
	#	'DISPLAY_NAME'     => "KernelSmith Dumb Service - User-mod",
	#	'STATE'	           => "4  RUNNING",
	#	'START_TYPE'       => "2   AUTO_START",
	#	'BINARY_PATH_NAME' => "C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted",
	#	'DEPENDENCIES'     => "PlugPlay,DumberService"
	#	<...etc...>
	# }
	#
	def win_parse_results(str)
		#print_status "Parsing results string: #{str}" if $blab
		tip = false
		hashish = Hash.new(nil)
		lastkey = nil
		str.each_line do |line|
			line.chomp! 
			line.gsub!("\t",' ') # lose any tabs
			if (tip == true && line =~ /^ + :/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this will NOT pickup the (NOT_STOPPABLE, NOT_PAUSABLE), see next, but it
				# 	 will pickup when there's multiple dependencies
				#print_status "Caught line continuation with :" if $blab
				arr = line.scan(/\w+/)
				val = arr.join(',') # join with commas, tho there is probably only one item in arr
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif (tip == true && line =~ /^ + \(/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this WILL pickup (NOT_STOPPABLE, NOT_PAUSABLE) etc
				#print_status "Caught line continuation with (" if $blab
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
	# Parses error output of some windows CLI commands and returns hash with the keys/vals detected
	#  always returns hash as follows but :errval only comes back from sc.exe using 'FAILED' keyword
	#
	# Note, most of the time the :errval will be nil, it's not usually provided
	#
	#
	#--- sc.exe error example
	# [SC] EnumQueryServicesStatus:OpenService FAILED 1060:
	# 
	# The specified service does not exist as an installed service.
	#--- END sc.exe error example
	# returns:
	# {
	#   :error  => "The specified service does not exist as an installed service",
	#   :errval => 1060
	# }
	# 
	#
	#--- reg.exe error example
	# ERROR: Invalid key name.
	# Type "REG QUERY /?" for usage.
	#--- END reg.exe error example
	# returns:
	# {
	#   :error  => "INVALID KEY NAME."
	#   :errval => nil
	# }
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
			#print_status "Found FAILED, ma is #{ma.inspect}" if $blab
			sa = ma[0].split(' ')
			#print_status "sa is #{sa.inspect}" if $blab
			hashish[:errval] = sa[1].chomp.to_i
			# above intended to capture the numbers after the word 'FAILED' as [:errval]
			ma = /^[^\[\n].+/.match(str)
			#print_status "ma is #{ma.inspect}" if $blab
			hashish[:error] = ma[0].chomp.strip
			# above intended to capture first non-empty line not starting with '[' or \n into [:error]
		else
			# do nothing, defaults are good
		end
		#print_error "Error hash:  #{hashish.inspect}" if $blab
		print_error "This error hash is optionally available:  #{hashish.pretty_inspect}"
		return hashish
	end

end

end
end
end
