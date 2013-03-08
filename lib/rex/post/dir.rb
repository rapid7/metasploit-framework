#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Post

###
#
# This class wraps the behavior of the Ruby Dir class against a remote entity.
# Refer to the Ruby documentation for expected behavior.
#
###
class Dir

	def Dir.entries(name)
		raise NotImplementedError
	end

	def Dir.foreach(name, &block)
		entries(name).each(&block)
	end

	def Dir.chdir(path)
		raise NotImplementedError
	end

	def Dir.mkdir(path)
		raise NotImplementedError
	end

	def Dir.pwd
		raise NotImplementedError
	end

	def Dir.getwd
		raise NotImplementedError
	end

	def Dir.delete(path)
		raise NotImplementedError
	end

	def Dir.rmdir(path)
		raise NotImplementedError
	end

	def Dir.unlink(path)
		raise NotImplementedError
	end
end

end; end # Post/Rex
