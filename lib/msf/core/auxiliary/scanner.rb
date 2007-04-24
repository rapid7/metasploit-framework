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
			OptInt.new('THREADS', [ true, "The number of concurrent threads", 1 ] )
		], Auxiliary::Scanner)
	
	# RHOST should not be used in scanner modules, only RHOSTS
	deregister_options('RHOST')
end


#
# The command handler when launched from the console
#
def run

	tl = []
	
	begin
	
	if (self.respond_to?('run_range'))
		return run_range(datastore['RHOSTS'])
	end
	
	if (self.respond_to?('run_host'))
		ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
		
		# Clear the host/port list
		self.scanner_lists_clear
		
		while (true)
			tl = []

			# Spawn threads for each host
			while (tl.length < datastore['THREADS'])
				ip = ar.next_ip
				break if not ip
				tl << Thread.new do
					begin
						self.target_host = ip
						run_host(ip)
					rescue ::Interrupt
						raise $!
					rescue ::Exception => e
						print_status("Error: #{e.to_s}")
					end
				end
			end
			
			# Exit once we run out of hosts
			if(tl.length == 0)
				break
			end
			
			# Wait for the threads
			tl.each { |t| t.join }
		end
		
		return
	end

	if (self.respond_to?('run_batch'))
	
		if (! self.respond_to?('run_batch_size'))
			print_status("This module needs to export run_batch_size()")
			return
		end
		
		size = run_batch_size()

		ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
					
		while(true)
			
			tl = []
		
			# Clear the host/port list
			self.scanner_lists_clear
								
			while (tl.length < datastore['THREADS'])
				
				batch = []

				# Create batches from each set
				while (batch.length < size)
					ip = ar.next_ip
					break if not ip
					batch << ip
				end
				
				# Create a thread for each batch
				if (batch.length > 0)
					tl << Thread.new do
						begin
							run_batch(batch)
						rescue ::Interrupt
							raise $!
						rescue ::Exception => e
							print_status("Error: #{e.to_s}")
						end
					end
				end
				
				# Exit once we run out of hosts
				if (tl.length == 0)
					break
				end
			end
			
			# Exit once we run out of hosts
			if (tl.length == 0)
				break
			end
			
			# Wait for the threads
			tl.each { |t| t.join }
		end
		
		return
	end

	print_status("This module defined no run_host or run_range methods")
	
	rescue ::Interrupt
		print_status("Caught interrupt from the console...")
		return
	ensure
		self.scanner_lists_clear
		tl.each do |t|
			begin
				t.kill
			rescue ::Exception
			end
		end
	end

end

def scanner_lists_clear
	self.scanner_hosts = {}
	self.scanner_ports = {}
	self.scanner_simples = {}
	self.scanner_dcerpcs = {}
	
	self.scanner_socks ||= {}
	self.scanner_socks.each_pair do |t,s|
		begin
			s.close
		rescue ::Exception
		end
	end

	self.scanner_udp_socks ||= {}	
	self.scanner_udp_socks.each_pair do |t,s|
		begin
			s.close
		rescue ::Exception
		end
	end	
end


#
# The hacks below allow Exploit mixins to be used inside of threaded
# Auxilliary modules that inherit from Scanner. Not the best solution,
# but they do the job for 90% of the common uses.
#


#
# Tracks the current hosts
#
attr_accessor :scanner_hosts, :scanner_ports, :scanner_socks, :scanner_udp_socks, :scanner_simples, :scanner_dcerpcs

#
# Overloads the Exploit mixins for rhost
#
def rhost
	self.target_host
end

#
# Provides a per-thread RHOST value
#
def target_host
	self.scanner_hosts ||= {}
	self.scanner_hosts[Thread.current.to_s]
end

#
# Sets a per-thread RHOST value
#
def target_host=(ip)
	self.scanner_hosts ||= {}
	self.scanner_hosts[Thread.current.to_s] = ip
end

#
# Overloads the Exploit mixins for rport
#
def rport
	self.target_port || datastore['RPORT']
end

#
# Provides a per-thread RPORT value
#
def target_port
	self.scanner_ports ||= {}
	self.scanner_ports[Thread.current.to_s]
end

#
# Sets a per-thread RPORT value
#
def target_port=(port)
	self.scanner_ports ||= {}
	self.scanner_ports[Thread.current.to_s] = port
end

#
# Provides a per-thread self.sock value
#
def sock
	self.scanner_socks ||= {}
	self.scanner_socks[Thread.current.to_s]
end

#
# Sets a per-thread self.sock value
#
def sock=(sock)
	self.scanner_socks ||= {}
	self.scanner_socks[Thread.current.to_s] = sock
end

#
# Provides a per-thread self.udp_sock value
#
def udp_sock
	self.scanner_udp_socks ||= {}
	self.scanner_udp_socks[Thread.current.to_s]
end

#
# Sets a per-thread self.udp_sock value
#
def udp_sock=(udp_sock)
	self.scanner_udp_socks ||= {}
	self.scanner_udp_socks[Thread.current.to_s] = udp_sock
end

#
# Provides a per-thread self.simple value
#
def simple
	self.scanner_simples ||= {}
	self.scanner_simples[Thread.current.to_s]
end

#
# Sets a per-thread self.simple value
#
def simple=(simple)
	self.scanner_simples ||= {}
	self.scanner_simples[Thread.current.to_s] = simple
end

#
# Provides a per-thread self.dcerpc value
#
def dcerpc
	self.scanner_dcerpcs ||= {}
	self.scanner_dcerpcs[Thread.current.to_s]
end

#
# Sets a per-thread self.dcerpc value
#
def dcerpc=(dcerpc)
	self.scanner_dcerpcs ||= {}
	self.scanner_dcerpcs[Thread.current.to_s] = dcerpc
end

end
end
