# -*- coding: binary -*-

module Msf
class Post
module Windows

module Mimikatz

  def load_kiwi
    if session.kiwi
      return true
    else
      begin
        if (session.platform =~ /x86/) and (sysinfo['Architecture'] =~ /64/)
          print_error "Attempted to load x86 Kiwi on an x64 architecture."
          return false
        else
          return session.core.use("kiwi")
        end
      rescue Errno::ENOENT
        print_error("Unable to load Kiwi.")
        return false
      end
    end
  end

  def load_mimikatz
    if session.mimikatz
      return true
    else
      begin
        if (session.platform =~ /x86/) and (sysinfo['Architecture'] =~ /64/)
          print_error "Attempted to load x86 Mimikatz on an x64 architecture."
          return false
        else
          return session.core.use("mimikatz")
        end
      rescue Errno::ENOENT
        print_error("Unable to load Mimikatz.")
        return false
      end
    end
  end

end # Mimikatz
end # Windows
end # Post
end # Msf
