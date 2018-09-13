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
    user_id = cmd_exec('id -u')
    clean_user_id = user_id.to_s.gsub(/[^\d]/, '')
    if clean_user_id.empty?
      raise "Could not determine UID: #{user_id.inspect}"
    end
    (clean_user_id == '0')
  end

end # Priv
end # Linux
end # Post
end # Msf
