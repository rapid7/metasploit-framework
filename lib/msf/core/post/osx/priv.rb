# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module OSX
module Priv
  include ::Msf::Post::Common

  #
  # Returns true if running as root, false if not.
  #
  def is_root?
    cmd_exec('/usr/bin/id -ru').eql? '0'
  end

  #
  # Returns true if session user is in the admin group, false if not.
  #
  def is_admin?
    cmd_exec('groups | grep -wq admin && echo true').eql? 'true'
  end
end
end
end
end
