module Msf

###
#
# This module provides methods for scanning modules
#
###

module Auxiliary::Scanner


#
# Initializes an instance of a recon auxiliary module
#
def initialize(info = {})
	super

	register_options(
		[
			OptAddressRange.new('RHOSTS', [ true, "The target address range or CIDR identifier"]),
		], Auxiliary::Scanner)
	
	# RHOST should not be used in scanner modules, only RHOSTS
	deregister_options('RHOST')
end


#
# The command handler when launched from the console
#
def run

	begin
	
	if (self.respond_to?('run_range'))
		return run_range(datastore['RHOSTS'])
	end
	
	# Add support for multiple threads
	if (self.respond_to?('run_host'))
		ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
		while(ip = ar.next_ip)
			self.target_host = ip
			run_host(ip)
		end
		return
	end

	# Add support for multiple threads
	if (self.respond_to?('run_batch'))
	
		if (! self.respond_to?('run_batch_size'))
			print_status("This module needs to export run_batch_size()")
			return
		end
		
		size = run_batch_size()

		ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
		while(true)
			batch = []
			
			while (batch.length < size)
				ip = ar.next_ip
				break if not ip
				batch << ip
			end
			return if batch.length == 0
			run_batch(batch)
		end
		return
	end
		
	print_status("This module defined no run_host or run_range methods")
	
	rescue ::Interrupt
		print_status("Caught interrupt from the console...")
		return
	end
end


#
# The current target host (replaces RHOST)
#
attr_accessor :target_host

#
# Overloads the Exploit mixins for rhost
#
def rhost
	self.target_host
end

end
end
