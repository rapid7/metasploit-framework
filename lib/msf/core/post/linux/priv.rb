# -*- coding: binary -*-
require 'msf/core/post/common'

module Msf
class Post
module Linux
module Priv
  include ::Msf::Post::Common

  #
  # Returns true if running as root, false if not.
  # @return [Boolean]
  #
  def is_root?
    if command_exists?("id")
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
    else
      user = whoami
      found = false
      data = cmd_exec("while read line; do echo $line; done </etc/passwd")
      data.each_line do |line|
        line = line.split(":")
        user_passwd = line[0]
        if user_passwd = user
    if line[1] = 0
            found = true
          end
        end
      end
      return found
    end
  end

end # Priv
end # Linux
end # Post
end # Msf
