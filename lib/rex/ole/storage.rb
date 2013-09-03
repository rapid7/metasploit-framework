# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class Storage

	attr_accessor :header

	def initialize(filename=nil, mode=STGM_READ)
		@mode = mode
		@modified = nil

		@fd = nil
		@filename = nil
		@header = Header.new
		@difat = DIFAT.new self
		@fat = FAT.new self
		@minifat = MiniFAT.new self
		@directory = Directory.new self
		@ministream = Stream.new self

		if (filename)
			@filename = filename
			open(filename, mode)
			return
		end
	end


	def each
		@directory.each { |el|
			yield el
		}
	end


	def name
		@filename
	end


	def open(filename, mode)
		if (mode == STGM_READWRITE)
			fmode = 'r+b'
		elsif (mode == STGM_WRITE)
			fmode = 'w+b'
		else
			fmode = 'rb'
		end

		@fd = File.new(filename, fmode)

		# don't read for new files
		if (mode == STGM_WRITE)
			# ensure there is a root
			write_to_disk
			return
		end

		# parse the header
		@header.read @fd
		@difat.read
		@fat.read @difat
		@minifat.read
		@directory.read
		# NOTE: we can't use read_stream_data here (must read using regular FAT, regardless of size)
		# read data using the root node's start/length
		@ministream << read_data(@directory)
	end

	def close
		if (@modified) and (@mode != STGM_READ)
			write_to_disk
		end
		@fd.close
	end

	def inspect
		ret = ""
		ret << "header = %s\n" % @header.to_s

		ret << "*** %u DIFAT sectors\n" % @difat.length
		ret << @difat.to_s << "\n"

		ret << "*** %u FAT sectors\n" % @fat.length
		ret << @fat.to_s << "\n"

		ret << "*** %u MiniFAT sectors:\n" % @minifat.length
		if (@minifat.length > 0)
			ret << @minifat.to_s << "\n"
		end

		ret << "*** ministream (%u bytes):\n" % @ministream.length
		if (@ministream.length > 0)
			ret << @ministream.to_s << "\n"
		end

		ret << "*** %u directory entries\n" % @directory.num_entries
		ret << @directory.to_s << "\n"
	end


	#
	# stream manipulation functions
	#
	def create_stream(name, mode=STGM_WRITE, parent_stg=nil)
		if (stm = open_stream(name, mode, parent_stg))
			stm.close
			return nil
		end

		# eek, don't check the name for now
		# if we do, we cant create alot of streams (summary info for example)
=begin
		if (not Util.name_is_valid(name))
			return nil
		end
=end

		stm = Stream.new self
		stm.name = name
		parent_stg ||= @directory
		dlog("Adding stream #{name} to storage #{parent_stg.name}", 'rex', LEV_3)
		@directory.link_item(parent_stg, stm)
		@modified = true
		stm
	end

	def open_stream(name, mode=STGM_READ, parent_stg=nil)
		parent_stg ||= @directory
		stm = parent_stg.find_stream_by_name_and_type(name, STGTY_STREAM)
		if (stm)
			# TODO: optimize out the need to read all of the data up-front
			stm << read_stream_data(stm)
		end
		stm
	end


	#
	# storage manipulation functions
	#
	def create_storage(name, mode=STGM_READ, parent_stg=nil)
		stg = SubStorage.new self
		stg.name = name
		parent_stg ||= @directory
		dlog("Adding storage #{name} to storage #{parent_stg.name}", 'rex', LEV_3)
		@directory.link_item(parent_stg, stg)
		stg
	end

	def open_storage(name, mode=STGM_READ, parent_stg=nil)
		@directory.find_stream_by_name_and_type(name, STGTY_STORAGE)
	end


	#
	# low-level functions
	#
	def write_to_disk
		# reset  FAT/DIFAT
		@difat = DIFAT.new self
		@fat = FAT.new self

		@header.write @fd
		write_user_data

		# NOTE: we call write_stream here since we MUST write this to
		# the regular stream (regardless of size)
		ms_start = write_stream(@ministream)
		@directory.set_ministream_params(ms_start, @ministream.length)

		@minifat.write
		@directory.write
		@fat.write(@difat)
		@difat.write

		# write it again, now that its complete
		@header.write @fd
		@fd.flush
	end

	def write_sector(sbuf, type=nil, prev_sect=nil)
		len = sbuf.length
		if (len != @header.sector_size)
			# pad it if less
			if (len < @header.sector_size)
				sbuf = sbuf.dup
				sbuf << "\x00" * (@header.sector_size - len)
			else
				raise RuntimeError, 'not sector sized!'
			end
		end

		# write the data
		idx = @fat.allocate_sector(type)
		# point previous sector to here
		if (prev_sect)
			@fat[prev_sect] = idx
		end
		write_sector_raw(idx, sbuf)
		return idx
	end

	def write_sector_raw(sect, sbuf)
		dlog("Writing sector 0x%02x" % sect, 'rex', LEV_3)
		@fd.seek((sect + 1) * @header.sector_size, ::IO::SEEK_SET)
		@fd.write(sbuf)
	end


	def write_mini_sector(sbuf, prev_sect=nil)
		len = sbuf.length
		if (len != @header.mini_sector_size)
			if (len < @header.mini_sector_size)
				sbuf = sbuf.dup
				sbuf << "\x00" * (@header.mini_sector_size - len)
			else
				raise RuntimeError, 'not mini sector sized!'
			end
		end

		idx = @minifat.allocate_sector
		# point the previous mini sector to here
		if (prev_sect)
			@minifat[prev_sect] = idx
		end
		write_mini_sector_raw(idx, sbuf)
		idx
	end

	def write_mini_sector_raw(sect, sbuf)
		dlog("Writing mini sector 0x%02x" % sect, 'rex', LEV_3)
		@ministream << sbuf
	end



	def write_user_data
		@directory.each_entry { |stm|
			# only regular streams this pass
			next if (stm.type != STGTY_STREAM)

			if (stm.length >= @header._ulMiniSectorCutoff)
				stm.start_sector = write_stream(stm)
			else
				# NOTE: stm_start is a minifat value
				stm.start_sector = write_mini_stream(stm)
			end
		}
	end

	def write_stream(stm)
		dlog("Writing \"%s\" to regular stream" % stm.name, 'rex', LEV_3)
		stm_start = nil
		prev_sect = nil
		stm.seek(0)
		while (sbuf = stm.read(@header.sector_size))
			sect = write_sector(sbuf, nil, prev_sect)
			stm_start ||= sect
			prev_sect = sect
		end
		stm_start
	end

	def write_mini_stream(stm)
		dlog("Writing \"%s\" to mini stream" % stm.name, 'rex', LEV_3)
		prev_sect = nil
		stm.seek(0)
		while (sbuf = stm.read(@header.mini_sector_size))
			sect = write_mini_sector(sbuf, prev_sect)
			stm_start ||= sect
			prev_sect = sect
		end
		stm_start
	end


	def read_stream_data(direntry)
		if (direntry.length < @header._ulMiniSectorCutoff)
			return read_data_mini(direntry)
		end

		read_data(direntry)
	end

	def read_data(direntry)
		ret = ""
		visited = []
		left = direntry.length
		sect = direntry.start_sector
		while (sect != SECT_END)
			if (visited.include?(sect))
				raise RuntimeError, 'Sector chain loop detected (0x%08x)' % sect
			end
			visited << sect

			# how much to read?
			block = @header.sector_size
			block = left if (block > left)

			# read it.
			dlog("read_data - reading 0x%x bytes" % block, 'rex', LEV_3)
			buf = read_sector(sect, block)
			ret << buf
			left -= buf.length

			# done?
			break if (left == 0)

			sect = next_sector(sect)
		end
		ret
	end

	def read_data_mini(direntry)
		ret = ""
		visited = []
		left = direntry.length
		sect = direntry.start_sector
		while (sect != SECT_END)
			if (visited.include?(sect))
				raise RuntimeError, 'Sector chain loop detected (0x%08x mini)' % sect
			end
			visited << sect

			# how much to read?
			block = @header.mini_sector_size
			block = left if (block > left)

			# read it.
			dlog("read_data_mini - reading 0x%x bytes" % block, 'rex', LEV_3)
			buf = read_mini_sector(sect, block)
			ret << buf
			left -= buf.length

			# done?
			break if (left == 0)

			sect = next_mini_sector(sect)
		end
		ret
	end


	def read_sector(sect, len)
		off = ((sect + 1) * @header.sector_size)
		@fd.seek(off, ::IO::SEEK_SET)
		buf = @fd.read(len)
		if (not buf)
			if (@fd.eof?)
				raise RuntimeError, 'EOF while reading sector data (0x%08x)' % sect
			else
				raise RuntimeError, 'Unknown error while reading sector data (0x%08x)' % sect
			end
		end
		if (buf.length != len)
			raise RuntimeError, 'Insufficient data for sector (0x%08x): got %u of %u' % [sect, buf.length, len]
		end
		buf
	end

	def next_sector(sect)
		return SECT_END if (sect >= @fat.length)
		@fat[sect]
	end


	def read_mini_sector(sect, len)
		dlog("Reading mini sector 0x%x" % sect, 'rex', LEV_3)
		off = (@header.mini_sector_size * sect)
		dlog("Reading from offset 0x%x of ministream" % off, 'rex', LEV_3)
		@ministream.seek(off)
		data = @ministream.read(len)
		data
	end

	def next_mini_sector(sect)
		return SECT_END if (sect >= @minifat.length)
		@minifat[sect]
	end

end

end
end
