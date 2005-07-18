module Msf
module Session

###
#
# Basic
# -----
#
# This class implements an interactive session using raw input/output in
# only the most basic fashion.
#
###
module Basic

	include Session
	include Interactive

	#
	# Description of the session
	#
	def desc
		"Basic I/O"
	end

	#
	# Basic session
	#
	def type
		"basic"
	end
	
protected

	#
	# Performs the actual raw interaction with the remote side.  This can be
	# overriden by derived classes if they wish to do this another way.
	#
	def _interact
		while self.interacting
			# Select input and rstream
			sd = Rex::ThreadSafe.select([ user_input.fd, rstream.fd ])

			# Cycle through the items that have data
			# From the rstream?  Write to user_output.
			sd[0].each { |s|
				if (s == rstream.fd)
					data = rstream.get

					user_output.print(data)
				# From user_input?  Write to rstream.
				elsif (s == user_input.fd)
					data = user_input.gets

					rstream.put(data)
				end
			} if (sd)
		end
	end

end

end
end
