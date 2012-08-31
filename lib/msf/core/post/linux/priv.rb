# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module Linux
module Priv
	include ::Msf::Post::Common

	#
	# Returns true if running as root, false if not.
	#
	def is_root?
		root_priv = false
		user_id = cmd_exec("id -u")
		clean_user_id = user_id.to_s.gsub(/[^\d]/,"")
		unless clean_user_id.empty?
			if clean_user_id =~ /^0$/
				root_priv = true
			elsif clean_user_id =~ /^\d*$/
				root_priv = false
			end
		else
			raise "Could not determine UID: #{user_id.inspect}"
		end
		return root_priv
	end

	def get_user_shell
		cmd = %q{while IFS=":" read -r a b c d e f g
		do 
		  echo :$c:$f:$g
		done < /etc/passwd | /bin/grep ":$(id -u):"}
		shell = cmd_exec(cmd).split(':')[3].gsub("\n", '').scan(/[a-zA-Z0-9]*$/)[0]
		shell
	end

end # Priv
end # Linux
end # Post
end # Msf
