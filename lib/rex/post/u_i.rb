#!/usr/bin/ruby

module Rex
module Post

###
#
# UI
# --
#
# User-interface interaction base class.
#
###
class UI

	def disable_keyboard
		raise NotImplementedError
	end

	def enable_keyboard
		raise NotImplementedError
	end

	def disable_mouse
		raise NotImplementedError
	end

	def enable_mouse
		raise NotImplementedError
	end

	def idle_time
		raise NotImplementedError
	end

end

end; end
