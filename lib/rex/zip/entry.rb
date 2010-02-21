##
# $Id$
##

module Rex
module Zip

class Entry

	attr_accessor :name, :flags, :info, :xtra, :comment, :attrs

	def initialize(fname, data, compmeth, timestamp=nil, attrs=nil, xtra=nil, comment=nil)
		@name = fname
		@data = data
		@xtra = xtra
		@xtra ||= ''
		@comment = comment
		@comment ||= ''
		@attrs = attrs
		@attrs ||= 0

		# XXX: sanitize timestmap (assume now)
		timestamp ||= Time.now
		@flags = CompFlags.new(0, compmeth, timestamp)

		if (@data)
			compress
		else
			@data = ''
			@info = CompInfo.new(0, 0, 0)
		end
		@compdata ||= ''
	end


	def compress
		@crc = Zlib.crc32(@data, 0)
		case @flags.compmeth

		when CM_STORE
			@compdata = @data

		when CM_DEFLATE
			z = Zlib::Deflate.new(Zlib::BEST_COMPRESSION)
			@compdata = z.deflate(@data, Zlib::FINISH)
			z.close
			@compdata = @compdata[2, @compdata.length-6]

		else
			raise 'Unsupported compression method: %u' % @flags.compmeth
		end

		# if compressing doesn't help, just store it
		if (@compdata.length > @data.length)
			@compdata = @data
			@flags.compmeth = CM_STORE
		end

		@info = CompInfo.new(@crc, @compdata.length, @data.length)
	end


	def relative_path
		if (@name[0,1] == '/')
			return @name[1,@name.length]
		end
		@name
	end


	def pack
		ret = ''

		#  - lfh 1
		lfh = LocalFileHdr.new(self)
		ret << lfh.pack

		#  - data 1
		if (@compdata)
			ret << @compdata
		end

		if (@gpbf & GPBF_USE_DATADESC)
			#  - data desc 1
			dd = DataDesc.new(@info)
			ret << dd.pack
		end

		ret
	end

end

end
end
