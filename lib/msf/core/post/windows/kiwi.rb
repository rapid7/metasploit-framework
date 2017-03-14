# -*- coding: binary -*-

module Msf
class Post
module Windows

module Kiwi

  def load_kiwi
    if session.kiwi
      return true
    else
      begin
        return session.core.use('kiwi')
      rescue Errno::ENOENT
        print_error('Unable to load Kiwi Mimikatz Extension.')
        return false
      end
    end
  end

end # Kiwi
end # Windows
end # Post
end # Msf
