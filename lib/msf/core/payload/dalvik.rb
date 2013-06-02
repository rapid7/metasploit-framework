# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Dalvik

	#
	# Fix the dex header checksum and signature
	# http://source.android.com/tech/dalvik/dex-format.html
	#
	def fix_dex_header(dexfile)
		dexfile = dexfile.unpack('a8LH40a*')
		dexfile[2] = Digest::SHA1.hexdigest(dexfile[3])
		dexfile[1] = Zlib.adler32(dexfile[2..-1].pack('H40a*'))
		dexfile.pack('a8LH40a*')
	end

	#
	# We could compile the .class files with dx here
	#
	def generate_stage
	end

	#
	# Used by stagers to construct the payload jar file as a String
	#
	def generate
		generate_jar.pack
	end

	def java_string(str)
		[str.length].pack("N") + str
	end

end

