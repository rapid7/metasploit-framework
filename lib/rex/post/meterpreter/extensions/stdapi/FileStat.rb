#!/usr/bin/ruby

require 'Rex/Post/FileStat'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# FileStat
# --------
#
# This class wrappers gathering information about a given file
#
###
class FileStat < Rex::Post::FileStat

	@@struct_stat = [
	  'st_dev',     4,  # 0
	  'st_ino',     2,  # 4
	  'st_mode',    2,  # 6
	  'st_nlink',   2,  # 8
	  'st_uid',     2,  # 10
	  'st_gid',     2,  # 12
	  'pad1',       2,  # 14
	  'st_rdev',    4,  # 16
	  'st_size',    4,  # 20
	  'st_atime',   4,  # 24
	  'st_mtime',   4,  # 28
	  'st_ctime',   4,  # 32
	]

	class <<self
		attr_accessor :client
	end

	##
	#
	# Constructor
	#
	##

	def initialize(file)
		self.stathash = stat(file)
	end

protected

	##
	#
	# Initializer
	#
	##

	# Gets information about the supplied file and returns a populated
	# hash to the requestor
	def stat(file)
		request = Packet.create_request('stdapi_fs_stat')

		request.add_tlv(TLV_TYPE_FILE_PATH, file)

		response = self.class.client.send_request(request)
		stat_buf = response.get_tlv(TLV_TYPE_STAT_BUF).value

		# Next, we go through the returned stat_buf and fix up the values
		# and insert them into a hash
		elem   = @@struct_stat
		hash   = {}
		offset = 0
		index  = 0

		while (index < elem.length)
			size = elem[index + 1]

			value   = stat_buf[offset, size].unpack(size == 2 ? 'S' : 'L')[0]
			offset += size

			hash[elem[index]] = value

			index += 2
		end

		return hash	
	end

end

end; end; end; end; end
