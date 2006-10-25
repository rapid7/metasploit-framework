#
# This class wraps the lorcon 802.11 packet injection library
# The real wrapper code can be found in msflorcon.c and features.rb
#

$:.unshift(File.join(File.dirname(__FILE__)))

class MSFLorcon

	LIBNAME = File.join(File.dirname(__FILE__), "msflorcon-" + RUBY_PLATFORM + ".so")
	
	require 'dl'

	@@loaded = nil

	def self.loaded
		@@loaded
	end

	def self.open(*args)
		nil
	end
		
	begin
		module LORCON
			LIB = DL.dlopen(LIBNAME)
			SYM = { }
		end	

		require 'features'
		
		@@loaded = true	
		
	rescue ::Exception => e
		$stderr.puts "Error loading the Lorcon features: #{e} #{e.backtrace.to_s}"
	end

end
