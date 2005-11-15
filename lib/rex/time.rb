module Rex

###
#
# Extended time related functions.
#
###
module ExtTime

	#
	# Convert seconds to a string that is broken down into years, days, hours,
	# minutes, and second.
	#
	def self.sec_to_s(seconds)
		parts = [ 31536000, 86400, 3600, 60, 1 ].map { |d|
			if ((c = seconds / d) > 0) 
				seconds -= c.truncate * d
				c.truncate
			else
				0
			end
		}.reverse

		str = ''

		[ "sec", "min", "hour", "day", "year" ].each_with_index { |name, idx|
			next if (!parts[idx] or parts[idx] == 0)

			str = "#{parts[idx]} #{name + ((parts[idx] != 1) ? 's' :'')} " + str
		}

		str
	end

end

end

