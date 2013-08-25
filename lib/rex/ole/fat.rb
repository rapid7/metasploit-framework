# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class FAT < DIFAT

	#
	# low-level functions
	#
	def read(difat)
		@entries = []
		cnt = left = @stg.header._csectFat
		difat.each { |fs|
			break if (left == 0)

			if (fs != SECT_FREE)
				buf = @stg.read_sector(fs, @stg.header.sector_size)
				arr = Util.get32array(buf)

				# hax!
				if (@entries[fs] == SECT_DIF)
					# chop the next ptr
					@entries += arr.slice!(0, arr.length - 1)
				else
					@entries += arr
				end
				left -= 1
			end
		}

		if (left != 0)
			raise RuntimeError, 'Only found %u of %u sectors' % [(cnt - left), cnt]
		end
	end

	def allocate_sector(type=nil)
		idx = @entries.index(SECT_FREE)
		if (not idx)
			# add a sector worth
			idx = @entries.length
			@stg.header.idx_per_sect.times {
				@entries << SECT_FREE
			}
		end

		# mark the sector as in use
		if (type)
			@entries[idx] = type
		else
			# default normal sectors to end of chain
			@entries[idx] = SECT_END
		end
		idx
	end

	def write(difat)
		# we build the difat as we write these..
		difat.reset

		# allocate the sectors
		fat_sects = []
		left = @entries.length
		while (left > 0)
			if (left > @stg.header.idx_per_sect)
				left -= @stg.header.idx_per_sect
			else
				left = 0
			end
			fat_sects << allocate_sector(SECT_FAT)
		end

		# write the fat into the difat/allocated sectors
		copy = @entries.dup
		fat_sects.each { |fs|
			part = copy.slice!(0, @stg.header.idx_per_sect)
			sbuf = Util.pack32array(part)

			if (sbuf.length != @stg.header.sector_size)
				raise RuntimeError, 'Unsupported number of fat sectors (not multiple of idx per sect)'
			end

			@stg.write_sector_raw(fs, sbuf)
			difat << fs
		}
	end

end

end
end
