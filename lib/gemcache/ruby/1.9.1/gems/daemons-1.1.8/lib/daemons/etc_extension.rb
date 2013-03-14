require 'etc'

Etc.instance_eval do
  def groupname(gid)
    Etc.group {|e| return e.name if gid == e.gid }
    nil
  end
  def username(uid)
    Etc.passwd {|e| return e.name if uid == e.uid }
    nil
  end
end
