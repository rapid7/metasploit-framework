# -*- coding: binary -*-

module Msf
class Post
module Windows

module ExtAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              extapi_*
            ]
          }
        }
      )
    )
  end

  def load_extapi
    if session.extapi
      return true
    else
      begin
        return session.core.use("extapi")
      rescue Errno::ENOENT
        print_error("Unable to load Extended API.")
        return false
      end
    end
  end

end # ExtAPI
end # Windows
end # Post
end # Msf
