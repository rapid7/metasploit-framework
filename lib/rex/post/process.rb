#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Post

###
#
# This class performs basic process operations against a process running on a
# remote machine via the post-exploitation mechanisms.  Refer to the Ruby
# documentation for expected behaviors.
#
###
class Process

  def Process.getresuid
    raise NotImplementedError
  end
  def Process.setresuid(a, b, c)
    raise NotImplementedError
  end

  def Process.euid
    getresuid()[1]
  end
  def Process.euid=(id)
    setresuid(-1, id, -1)
  end
  def Process.uid
    getresuid()[0]
  end
  def Process.uid=(id)
    setresuid(id, -1, -1)
  end

  def Process.egid
    getresgid()[1]
  end
  def Process.egid=(id)
    setresgid(-1, id, -1)
  end
  def Process.gid
    getresgid()[0]
  end
  def Process.gid=(id)
    setresgid(id, -1, -1)
  end

  def Process.pid
    raise NotImplementedError
  end
  def Process.ppid
    raise NotImplementedError
  end

end

end; end # Post/Rex
