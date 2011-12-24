require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'

module Msf
class Post
module Windows
module Railgun

	# Go through each method and add a convenience method
	Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Railgun.builtin_dlls.each do |api|
		# We will be interpolating within an eval. We exercise due paranoia.
		unless api.to_s =~ /^\w+$/
			print_error 'Something is seriously wrong with Railgun.BUILTIN_DLLS list'
			next
		end

		# don't override existing methods
		if method_defined? api.to_sym
			# We don't warn in case the override is intentional
			next
		end

		# evaling a String is faster than calling define_method 
		eval "def #{api.to_s}; railgun.#{api.to_s}; end"
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
