# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module Osx
module Priv
	include ::Msf::Post::Common

	# Returns true if running as root, false if not.
	def is_root?
		name = cmd_exec("whoami")
		if name == 'root'
			return true
		else
			return false
		end
	end

end 
end 
end 
end 
