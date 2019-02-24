# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module Solaris
module Priv
  include ::Msf::Post::Common

  #
  # Returns true if running as root, false if not.
  #
  def is_root?
    root_priv = false
    user_id = cmd_exec("/usr/xpg4/bin/id -u")
    if user_id.to_i == 0
      root_priv = true
    end
    return root_priv
  end

end # Priv
end # Solaris
end # Post
end # Msf
