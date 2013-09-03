# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

class Stream < DirEntry

	def initialize(stg)
		super

		# for reading/writing from this
		@offset = 0
		@_mse = STGTY_STREAM
	end

	def close
		@mode = nil
		@offset = nil
	end

	def seek(offset)
		@offset = offset
	end

	def read(len)
		return nil if (not @data)

		ret = @data[@offset, len]
		@offset += len
		ret
	end

	def <<(expr)
		if (not @data)
			@data = expr.dup
		else
			@data << expr
		end
		@_ulSize = @data.length
	end

end

end
end
