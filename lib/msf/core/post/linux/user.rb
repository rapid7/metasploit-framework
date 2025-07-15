# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module User
        #
        # Returns a string of the user's home directory
        #
        def get_home_dir(user)
          cmd_exec("grep '^#{user}:' /etc/passwd | cut -d ':' -f 6").chomp
          # could also be: "getent passwd #{user} | cut -d: -f6"
        end
        # User
      end
      # Linux
    end
    # Post
  end
  # Msf
end