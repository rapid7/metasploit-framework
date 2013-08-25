# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class DIFAT

	def initialize stg
		@stg = stg
		@entries = []
	end

	#
	# convenience access to entries
	#
	def []=(idx,expr)
		@entries[idx] = expr
	end

	def [](idx)
		@entries[idx]
	end

	def +(expr)
		@entries += expr
		self
	end

	def <<(expr)
		@entries << expr
	end

	def length
		@entries.length
	end

	def slice!(start,stop)
		@entries.slice!(start,stop)
	end

	def reset
		@entries = []
	end

	def each
		@entries.each { |el|
			yield el
		}
	end

	#
	# woop
	#
	def to_s
		ret = "{ "
		@entries.each { |el|
			ret << ", " if (ret.length > 2)
			case el
			when SECT_END
				ret << "END"
			when SECT_DIF
				ret << "DIF"
			when SECT_FAT
				ret << "FAT"
			when SECT_FREE
				ret << "FREE"
			else
				ret << "0x%x" % el
			end
		}
		ret << " }"
		ret
	end

	#
	# low-level functions
	#
	def read
		@entries = []

		# start with the header part
		@entries += @stg.header._sectFat

		# double indirect fat
		sect = @stg.header._sectDifStart
		while (sect != SECT_END)
			if (@entries.include?(sect))
				raise RuntimeError, 'Sector chain loop detected (0x%08x)' % sect
			end

			@entries << sect
			buf = @stg.read_sector(sect, @stg.header.sector_size)

			# the last sect ptr in the block becomes the next entry
			sect = Util.get32(buf, ((@stg.header.idx_per_sect)-1) * 4)
		end

		# don't need these free ones, but it doesn't hurt to keep them.
		#@difat.delete(SECT_FREE)
	end

	def write
		len = @entries.length
		first109 = @entries.dup

		rest = nil
		if (len > 109)
			rest = first109.slice!(109,len)
		end

		@stg.header._sectFat = []
		@stg.header._sectFat += first109
		if (len < 109)
			need = 109 - len
			need.times {
				@stg.header._sectFat << SECT_FREE
			}
		end

		if (rest and rest.length > 0)
			raise RuntimeError, 'TODO: support writing DIF properly!'
			# may require adding more fat sectors :-/
			#@stg.header._csectDif = rest.length
			#@stg.header._sectDifStart = idx
		end

		@stg.header._csectFat = len
	end

end

end
end
