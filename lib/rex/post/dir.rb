#!/usr/bin/ruby

module Rex
module Post

class Dir

	def Dir.entries(name)
		throw NotImplementedError
	end

	def Dir.foreach(name, &block)
		entries(name).each(&block)
	end
end

end; end # Post/Rex

