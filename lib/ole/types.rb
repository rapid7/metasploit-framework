require 'ole/base'

module Ole # :nodoc:
	# FIXME
	module Types
		# Parse two 32 bit time values into a DateTime
		# Time is stored as a high and low 32 bit value, comprising the
		# 100's of nanoseconds since 1st january 1601 (Epoch).
		# struct FILETIME. see eg http://msdn2.microsoft.com/en-us/library/ms724284.aspx
		def self.load_time str
			low, high = str.unpack 'L2'
			time = EPOCH + (high * (1 << 32) + low) * 1e-7 / 86400 rescue return
			# extra sanity check...
			unless (1800...2100) === time.year
				Log.warn "ignoring unlikely time value #{time.to_s}"
				return nil
			end
			time
		end

		# turn a binary guid into something displayable.
		# this will probably become a proper class later
		def self.load_guid str
			"{%08x-%04x-%04x-%02x%02x-#{'%02x' * 6}}" % str.unpack('L S S CC C6')
		end
	end
end