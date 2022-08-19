# -*- coding: binary -*-

module Msf
class Post
module Windows

module ExtAPI

  def load_extapi
    if session.respond_to?(:extapi) && session.extapi
      return true
    end

    if session.respond_to?(:core)
      return session.core.use('extapi')
    end

    false
  rescue Errno::ENOENT
    print_error('Unable to load Extended API.')
    false
  end

end # ExtAPI
end # Windows
end # Post
end # Msf
