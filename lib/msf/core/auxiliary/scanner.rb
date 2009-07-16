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

	threads_max = datastore['THREADS']
	tl = []
	
	#
	# Sanity check threading on different platforms
	#
	
	if(Rex::Compat.is_windows)
		if(threads_max > 16)
			print_error("Warning: The Windows platform cannot reliably support more than 16 threads")
			print_error("Thread count has been adjusted to 16")
			threads_max = 16
		end
	end

	if(Rex::Compat.is_cygwin)
		if(threads_max > 200)
			print_error("Warning: The Cygwin platform cannot reliably support more than 200 threads")
			print_error("Thread count has been adjusted to 200")
			threads_max = 200
		end
	end
	
	begin
	
	if (self.respond_to?('run_range'))
		return run_range(datastore['RHOSTS'])
	end
	
	if (self.respond_to?('run_host'))
		ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
		
		tl = []

		while (true)
			# Spawn threads for each host
			while (tl.length < threads_max)
				ip = ar.next_ip
				break if not ip
				
				tl << Thread.new(ip.dup) do |tip|
					targ = tip
					nmod = self.replicant
					nmod.datastore['RHOST'] = targ

					begin
						nmod.run_host(targ)
					rescue ::Interrupt
						raise $!
					rescue ::Rex::ConnectionError
					rescue ::Exception => e
						print_status("Error: #{targ}: #{e.message}")
						elog("Error running against host #{targ}: #{e.message}\n#{e.backtrace.join("\n")}")
					end
				end
			end
			
			# Exit once we run out of hosts
			if(tl.length == 0)
				break
			end

			# Assume that the oldest thread will be one of the
			# first to finish and wait for it.  After that's
			# done, remove any finished threads from the list
			# and continue on.  This will open up at least one
			# spot for a new thread
			tl.first.join
			tl.delete_if { |t| not t.alive? }
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
					
		tl = []

		while(true)
			nohosts = false	
			while (tl.length < threads_max)
				
				batch = []

				# Create batches from each set
				while (batch.length < size)
					ip = ar.next_ip
					if (not ip)
						nohosts = true
						break
					end
					batch << ip
				end
				
				# Create a thread for each batch
				if (batch.length > 0)
					tl << Thread.new(batch) do |bat|
						nmod = self.replicant
						mybatch = bat.dup
						begin
							nmod.run_batch(mybatch)
						rescue ::Interrupt
							raise $!
						rescue ::Rex::ConnectionError
						rescue ::Exception => e
							print_status("Error: #{mybatch[0]}-#{mybatch[-1]}: #{e}")
						end
					end
				end
				
				# Exit once we run out of hosts
				if (tl.length == 0 or nohosts)
					break
				end
			end

			# Exit if there are no more pending threads
			if (tl.length == 0)
				break
			end			

			# Assume that the oldest thread will be one of the
			# first to finish and wait for it.  After that's
			# done, remove any finished threads from the list
			# and continue on.  This will open up at least one
			# spot for a new thread
			tl.first.join
			tl.delete_if { |t| not t.alive? }
		end
		
		return
	end

	print_error("This module defined no run_host, run_range or run_batch methods")
	
	rescue ::Interrupt
		print_status("Caught interrupt from the console...")
		return
	ensure
		tl.each do |t|
			begin
				t.kill
			rescue ::Exception
			end
		end
	end

end

end
end
