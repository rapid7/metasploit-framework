##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

module Msf

module Auxiliary::Web
module Analysis::Timing

	TIME_STUB = '__TIME__'

	#
	# Performs timeout/time-delay analysis and logs an issue should there be one.
	#
	#
	# opts - Options Hash (default: {})
    #        :timeout - amount of seconds to wait for the request to complete
    #        :multi - __TIME__ = timeout * multi
	#
	def timeout_analysis( opts = {} )
		multi   = opts[:multi]   || 1
		timeout = opts[:timeout] || 5

		permutations.each do |p|
			seed = p.altered_value.dup

			# 1st pass, make sure the webapp is responsive
			next if !responsive?

			# 2nd pass, see if we can manipulate the response times
			timeout += 1
			p.altered_value = seed.gsub( TIME_STUB, (timeout * multi).to_s )
			next if p.responsive?( timeout - 1 )

			# 3rd pass, make sure that the previous step wasn't a fluke (like a dead web server)
			next if !responsive?

			# 4th pass, increase the delay and timeout to make sure that we are the ones
			# manipulating the webapp and this isn't all a coincidence
			timeout *= 2
			timeout += 1
			p.altered_value = seed.gsub( TIME_STUB, (timeout * multi).to_s )
			next if p.responsive?( timeout - 1 )

			# log it!
			fuzzer.process_vulnerability( p, 'Manipulatable response times.',
				:payload => p.altered_value )
		end
	end

	def responsive?( timeout = 120 )
		begin
			submit :retries => 0, :timeout => timeout
			true
		rescue Timeout::Error
			false
		end
	end

end
end
end
