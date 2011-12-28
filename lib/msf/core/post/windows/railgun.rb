require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'

module Msf
class Post
module Windows
module Railgun

	# Go through each dll and add a corresponding convenience method of the same name
	Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Railgun.builtin_dlls.each do |api|
		# We will be interpolating within an eval. We exercise due paranoia.
		unless api.to_s =~ /^\w+$/
			print_error 'Something is seriously wrong with Railgun.BUILTIN_DLLS list'
			next
		end

		# don't override existing methods
		if method_defined? api.to_sym
			# We don't warn as the override may have been intentional
			next
		end

		# evaling a String is faster than calling define_method 
		eval "def #{api.to_s}; railgun.#{api.to_s}; end"
	end

	#
	# Return an array of windows constants names matching +winconst+
	#
	def select_const_names(winconst, filter_regex=nil)
		return railgun.constant_manager.select_const_names(winconst, filter_regex)
	end

	#
	# Returns an array of windows error code names for a given windows error code matching +err_code+ 
	#
	def error_lookup (err_code)
		return select_const_names(err_code, /^ERROR_/)
	end

	def memread(address, length)
		railgun.memread(address, length)
	end

	def memwrite(address, length)
		railgun.memwrite(address, length)
	end

	def railgun
		client.railgun
	end
end
end
end
end
