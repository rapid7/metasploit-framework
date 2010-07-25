module Msf
module Scripts
module Meterpreter
module Common
	
#Writes a given string to a file specified
def file_local_write(file2wrt, data2wrt)
	if not ::File.exists?(file2wrt)
		::FileUtils.touch(file2wrt)
	end

	output = ::File.open(file2wrt, "a")
	data2wrt.each_line do |d|
		output.puts(d)
	end
	output.close
end
#Returns a MD5 checksum of a given local file
def file_local_digestmd5(file2md5)
	if not ::File.exists?(file2md5)
		raise "File #{file2md5} does not exists!"
	else
		require 'digest/md5'
		chksum = nil
		chksum = Digest::MD5.hexdigest(::File.open(file2md5, "rb") { |f| f.read})
		return chksum
	end
end
#Returns a SHA1 checksum of a given local file
def file_local_digestsha1(file2sha1)
	if not ::File.exists?(file2sha1)
		raise "File #{file2sha1} does not exists!"
	else
		require 'digest/sha1'
		chksum = nil
		chksum = Digest::SHA1.hexdigest(::File.open(file2sha1, "rb") { |f| f.read})
		return chksum
	end
end
#Returns a SHA256 checksum of a given local file
def file_local_digestsha2(file2sha2)
	if not ::File.exists?(file2sha2)
		raise "File #{file2sha2} does not exists!"
	else
		require 'digest/sha2'
		chksum = nil
		chksum = Digest::SHA256.hexdigest(::File.open(file2sha2, "rb") { |f| f.read})
		return chksum
	end
end

end
end
end
end

