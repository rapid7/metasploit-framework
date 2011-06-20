require 'msf/core/post/common'

module Msf
class Post
module Linux
module Priv
	include ::Msf::Post::Common

		# Returns true if running as root, false if not.
		def is_root?
			root_priv = false
			user_id = cmd_exec("id -u")
			if user_id.to_i == 0
				root_priv = true
			elsif user_id =~ /^\d*$/
				root_priv = false
			else
				raise "Could not determine UID: #{user_id}"
			end
			return root_priv
		end

end # Priv
end # Linux
end # Post
end # Msf
