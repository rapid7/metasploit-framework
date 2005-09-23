require 'timeout'

module Rex

###
# 
# ThreadSafe
# ----------
#
# This module provides a set of methods for performing various blocking
# operations in a manner that is compatible with ruby style threads.
#
###
module ThreadSafe

	DefaultCycle = 0.2

	#
	# Wraps calls to select with a lower timeout period and does the
	# calculations to walk down to zero timeout.  This has a little room for
	# improvement in that it should probably check how much time actually
	# elapsed during the select call considering ruby threading wont be exactly
	# accurate perhaps.
	#
	def self.select(rfd = nil, wfd = nil, efd = nil, t = nil)
		left = t

		begin
			# Poll the set supplied to us at least once.
			rv = ::IO.select(rfd, wfd, efd, DefaultCycle)

			return rv if (rv)

			# Decrement the amount of time left by the polling cycle
			left -= DefaultCycle if (left)

			# Keep chugging until we run out of time, if time was supplied.
		end while ((left == nil) or (left > 0))
	end

	#
	# Simulates a sleep operation by selecting on nil until a timeout period
	# expires.
	#
	def self.sleep(seconds)
		self.select(nil, nil, nil, seconds)

		seconds
	end

end

end
