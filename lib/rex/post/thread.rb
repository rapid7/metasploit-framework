#!/usr/bin/ruby

module Rex
module Post

class Thread
	
	def suspend
		raise NotImplementedError
	end
	
	def resume
		raise NotImplementedError
	end
	
	def terminate
		raise NotImplementedError
	end
	
	def query_regs
		raise NotImplementedError
	end
	
	def set_regs
		raise NotImplementedError
	end

	def close
		raise NotImplementedError
	end
end

end; end
