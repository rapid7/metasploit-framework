# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class MiniFAT < DIFAT

	#
	# low-level functions
	#
	def read
		@entries = []

		visited = []
		sect = @stg.header._sectMiniFatStart
		@stg.header._csectMiniFat.times { |idx|
			break if sect == SECT_END

			if (visited.include?(sect))
				raise RuntimeError, 'Sector chain loop detected (0x%08x)' % sect
			end
			visited << sect

			buf = @stg.read_sector(sect, @stg.header.sector_size)
			@stg.header.idx_per_sect.times { |idx|
				@entries << Util.get32(buf, (idx*4))
			}
			sect = @stg.next_sector(sect)
		}
	end

	def allocate_sector
		idx = @entries.index(SECT_FREE)

		if (not idx)
			# add a sector worth
			idx = @entries.length
			@stg.header.idx_per_sect.times {
				@entries << SECT_FREE
			}
		end

		# default mini-sectors to end of chain
		@entries[idx] = SECT_END
		idx
	end

	def write
		return if (@entries.length < 1)

		mf_start = nil
		mfs_count = 0
		prev_sect = nil
		copy = @entries.dup
		while (copy.length > 0)
			part = copy.slice!(0, @stg.header.idx_per_sect)
			sbuf = Util.pack32array(part)
			idx = @stg.write_sector(sbuf, nil, prev_sect)
			mfs_count += 1
			mf_start ||= idx
		end
		@stg.header._sectMiniFatStart = mf_start
		@stg.header._csectMiniFat = mfs_count
	end

end

end
end
