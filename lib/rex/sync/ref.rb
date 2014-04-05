# -*- coding: binary -*-
require 'thread'

module Rex

###
#
# This module provides a uniform reference counted interface for classes to
# use.
#
###
module Ref

  #
  # Initializes the reference count to one.
  #
  def refinit
    @_references       = 1
    @_references_mutex = Mutex.new

    self
  end

  #
  # Increments the total number of references.
  #
  def ref
    @_references_mutex.synchronize {
      @_references += 1
    }

    self
  end

  #
  # Decrements the total number of references.  If the reference count
  # reaches zero, true is returned.  Otherwise, false is returned.
  #
  def deref
    @_references_mutex.synchronize {
      if ((@_references -= 1) == 0)
        cleanup

        true
      else
        false
      end
    }
  end

  #
  # Called to clean up resources once the ref count drops to zero.
  #
  def cleanup
  end

end
end
