#
# This is a Ruby port of the Python manifest parsing code posted to:
# 	http://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup/3130860#3130860
#
# The script is updated to support iOS 5 & iOS 6 backups : by Satish B (satishb3) - www.securitylearn.net
# Reference: http://code.google.com/p/iphone-dataprotection/source/browse/python_scripts/backups/backup4.py
#

require 'digest/sha1'
module Rex
module Parser
class AppleBackupManifestDB

	attr_accessor :entry_offsets
	attr_accessor :entries
	attr_accessor :mbdb
	attr_accessor :mbdb_data
	attr_accessor :mbdb_offset
	
	def initialize(mbdb_data)	

		self.entries = {}
		self.entry_offsets = {}
		self.mbdb_data = mbdb_data
		parse_mbdb
		
	end
		
	def parse_mbdb
		raise ArgumentError, "Not valid MBDB data" if self.mbdb_data[0,6] != "mbdb\x05\x00"	
		self.mbdb_offset = 6

		while self.mbdb_offset < self.mbdb_data.length
			info 			 = {}
			info[:domain]      	 = mbdb_read_string
			info[:filename]    	 = mbdb_read_string		
			info[:linktarget]  	 = mbdb_read_string			
			info[:datahash]    	 = mbdb_read_string
			info[:encryptionkey]     = mbdb_read_string
			info[:mode]         	 = mbdb_read_int(2)
			info[:inodenumber]       = mbdb_read_int(8)			
			info[:uid]        	 = mbdb_read_int(4)				
			info[:gid]          	 = mbdb_read_int(4)				
			info[:mtime]        	 = Time.at(mbdb_read_int(4))
			info[:atime]        	 = Time.at(mbdb_read_int(4))
			info[:ctime]       	 = Time.at(mbdb_read_int(4))
			info[:length]       	 = mbdb_read_int(8)	
			info[:protectionClass]   = mbdb_read_int(1)
			property_count      	 = mbdb_read_int(1)
			info[:properties]   	 = {}
			1.upto(property_count) do |i|
				k = mbdb_read_string
				v = mbdb_read_string
				info[:properties][k] = v
			end

			filepath=info[:domain]+'-'+info[:filename]
			info[:fname]=Digest::SHA1.hexdigest filepath
			self.entry_offsets[ info[:fname] ] = info
		end

		self.mbdb_data = ""
	end
    	
	def mbdb_read_string
		raise RuntimeError, "Corrupted MBDB file" if self.mbdb_offset > self.mbdb_data.length
		len = self.mbdb_data[self.mbdb_offset, 2].unpack("n")[0]
		self.mbdb_offset += 2
		return '' if len == 65535
		val = self.mbdb_data[self.mbdb_offset, len]
		self.mbdb_offset += len
		return val
	end
	
	def mbdb_read_int(size)
		val = 0
		size.downto(1) do |i|
			val = (val << 8) + self.mbdb_data[self.mbdb_offset, 1].unpack("C")[0]
			self.mbdb_offset += 1
		end
 		val
	end
	
end

end
end
