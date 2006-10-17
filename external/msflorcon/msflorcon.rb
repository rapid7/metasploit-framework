#
# This class wraps the lorcon 802.11 packet injection library
# The real wrapper code can be found in msflorcon.c and features.rb
#

class MSFLorcon

	LIBNAME = File.join(File.dirname(__FILE__), "msflorcon-" + RUBY_PLATFORM + ".so")
	
	require 'dl'

	@@loaded = false

	def self.loaded
		@@loaded
	end

	begin
		module LORCON
			LIB = DL.dlopen(LIBNAME)
			SYM = { }
		end	
		
		@@loaded = true

		require 'features.rb'
		
	rescue ::Exception => e
	end
end
