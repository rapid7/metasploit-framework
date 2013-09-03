# -*- coding: binary -*-

module Msf
class Post
module Windows

module CliParse

	require 'msf/windows_error'
	require 'rex/logging'
	require 'rex/exceptions'

	#Msf::Post::Windows::CliParse::ParseError
	class ParseError < ArgumentError

		#
		# Create a new ParseError object. Expects a method name, an error
		# message, an error code, and the command that caused the error.
		#
		def initialize(method, einfo='', ecode=nil, clicmd=nil)
			@method = method
			@info = einfo
			# try to look up info if not given, but code is?
			@code   = ecode
			@clicmd = clicmd || "Unknown shell command"
		end

		#
		# Convert a ParseError to a string.
		#
		def to_s
			"#{@method}: Operation failed: #{@info}:#{@code} while running #{@clicmd}"
		end

		# The method that failed.
		attr_reader :method

		# The error info that occurred, typically a windows error message.
		attr_reader :info

		# The error result that occurred, typically a windows error code.
		attr_reader :code

		# The shell command that caused the error, if known
		attr_reader :clicmd
	end

	#
	# Parses output of some windows CLI commands and returns a hash with the
	# keys/vals detected.  If the item has multiple values, they will all be
	# returned in the val separated by commas. Keys are downcased and
	# symbolized (key.downcase.to_sym)
	#
	# sc.exe example (somewhat contrived):
	#    SERVICE_NAME: dumbservice
	#    DISPLAY_NAME: KernelSmith Dumb Service - User-mode
	#    TYPE               : 20  WIN32_SHARE_PROCESS
	#    STATE              : 4  RUNNING
	#                            (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
	#    START_TYPE         : 2   AUTO_START
	#    BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
	#    DEPENDENCIES       : PlugPlay
	#                       : DumberService
	#    SERVICE_START_NAME : LocalSystem
	#
	# returns:
	#    {
	#      :service_name     => "dumbservice",
	#      :display_name     => "KernelSmith Dumb Service - User-mod",
	#      :state            => "4  RUNNING",
	#      :start_type       => "2   AUTO_START",
	#      :binary_path_name => "C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted",
	#      :dependencies     => "PlugPlay,DumberService"
	#      <...etc...>
	#    }
	#
	def win_parse_results(str)
		tip = false
		hashish = {}
		lastkey = nil
		str.each_line do |line|
			line.chomp!
			line.gsub!("\t",' ') # lose any tabs
			if (tip == true && line =~ /^ + :/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this will NOT pickup the (NOT_STOPPABLE, NOT_PAUSABLE), see next, but it
				# 	 will pickup when there's multiple dependencies
				arr = line.scan(/\w+/)
				val = arr.join(',') # join with commas, tho there is probably only one item in arr
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif (tip == true && line =~ /^ + \(/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this WILL pickup (NOT_STOPPABLE, NOT_PAUSABLE) etc
				arr = line.scan(/\w+/) # put each "word" into an array
				val = arr.join(',') # join back together with commas in case comma wasn't the sep
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif line =~ /^ *[A-Z]+[_]*[A-Z]+.*:/
				tip = true
				arr = line.split(':')
				k = arr[0].strip.downcase.to_sym
				# grab all remaining fields for hash val in case ':' present in val
				v = arr[1..-1].join(':').strip
				# now add this entry to the hash
				hashish[k] = v
				lastkey = k
			end
		end
		return hashish
	end

	#
	# Parses error output of some windows CLI commands and returns hash with
	# the keys/vals detected always returns hash as follows but :errval only
	# comes back from sc.exe using 'FAILED' keyword
	#
	# Note, most of the time the :errval will be nil, it's not usually provided
	#
	#
	# sc.exe error example:
	#    [SC] EnumQueryServicesStatus:OpenService FAILED 1060:
	#
	#    The specified service does not exist as an installed service.
	# returns:
	#    {
	#      :error  => "The specified service does not exist as an installed service",
	#      :errval => 1060
	#    }
	#
	# reg.exe error example:
	#    ERROR: Invalid key name.
	#    Type "REG QUERY /?" for usage.
	# returns:
	#    {
	#      :error  => "INVALID KEY NAME."
	#      :errval => nil
	#    }
	#
	def win_parse_error(results)
		hashish = {
			:error => "Unknown Error",
			:errval => nil
		}
		# parse the results
		if ma = /^error:.*/i.match(results) # if line starts with Error: just pass to regular parser
			hashish.merge!(win_parse_results(ma[0].upcase)) #upcase required to satisfy regular parser
			# merge results.  Results from win_parse_results will override any duplicates in hashish
		elsif ma = /FAILED +[0-9]+/.match(results) # look for 'FAILED ' followed by some numbers
			sa = ma[0].split(' ')
			hashish[:errval] = sa[1].chomp.to_i
			# ^ intended to capture the numbers after the word 'FAILED' as [:errval]
			ma = /^[^\[\n].+/.match(results)
			hashish[:error] = ma[0].chomp.strip
			# above intended to capture first non-empty line not starting with '[' or \n into [:error]
		else
			# do nothing, defaults are good
		end
		return hashish
	end

end

end
end
end
