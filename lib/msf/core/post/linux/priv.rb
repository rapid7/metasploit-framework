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
    if command_exists?('id')
      user_id = cmd_exec('id -u')
      clean_user_id = user_id.to_s.gsub(/[^\d]/, '')
      if clean_user_id.empty?
        raise "Could not determine UID: #{user_id.inspect}"
      end
      return clean_user_id.match(/^0$/) ? true : false
    end

    user = whoami
    data = cmd_exec('while read line; do echo $line; done </etc/passwd')
    data.each_line do |line|
      line = line.split(':')
      return true if line[0] == user && line[3].to_i == 0
    end

    false
  end

end # Priv
end # Linux
end # Post
end # Msf
