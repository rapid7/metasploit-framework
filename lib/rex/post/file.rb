#!/usr/bin/ruby

module Rex
module Post

class File

	#
	# Class Methods
	#

	# setup a class variable for our client pointer
#	class <<self
#		attr_accessor :client
#	end

#	def File.stat(file)
#		return client.filestat.new(file)
#	end

#	def File.stat_hash(file)
#		raise NotImplementedError
#	end

	#
	# autogen'd stat passthroughs
	#
	def File.atime(name)
		stat(name).atime
	end
	def File.blockdev?(name)
		stat(name).blockdev?
	end
	def File.chardev?(name)
		stat(name).chardev?
	end
	def File.ctime(name)
		stat(name).ctime
	end
	def File.directory?(name)
		stat(name).directory?
	end
	def File.executable?(name)
		stat(name).executable?
	end
	def File.executable_real?(name)
		stat(name).executable_real?
	end
	def File.file?(name)
		stat(name).file?
	end
	def File.ftype(name)
		stat(name).ftype
	end
	def File.grpowned?(name)
		stat(name).grpowned?
	end
	def File.mtime(name)
		stat(name).mtime
	end
	def File.owned?(name)
		stat(name).owned?
	end
	def File.pipe?(name)
		stat(name).pipe?
	end
	def File.readable?(name)
		stat(name).readable?
	end
	def File.readable_real?(name)
		stat(name).readable_real?
	end
	def File.setuid?(name)
		stat(name).setuid?
	end
	def File.setgid?(name)
		stat(name).setgid?
	end
	def File.size(name)
		stat(name).size
	end
	def File.socket?(name)
		stat(name).socket?
	end
	def File.sticky?(name)
		stat(name).sticky?
	end
	def File.symlink?(name)
		stat(name).symlink?
	end
	def File.writeable?(name)
		stat(name).writeable?
	end
	def File.writeable_real?(name)
		stat(name).writeable_real?
	end
	def File.zero?(name)
		stat(name).zero?
	end



	#
	# Instance Methods
	#
	
	# setup an instance variable, just for ease and copy it over..
	# and so you can change it instance wise
#	private
#	attr_accessor :client
#	public

#	def initialize()
#		self.client = self.class.client
#	end


end

end; end # Post/Rex
