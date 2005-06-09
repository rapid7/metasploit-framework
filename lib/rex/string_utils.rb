#!/usr/bin/ruby

module Rex
module StringUtils

	#
	# Return the index of the first badchar in data, otherwise return
	# nil if there wasn't any badchar occurences.
	#
	def self.badchar_index(data, badchars)
		badchars.each_byte { |badchar|
			pos = data.index(badchar)
			return pos if pos
		}
		return nil
	end

	def self.remove_badchars(data, badchars)
		data.delete(badchars)
	end


end end
