# -*- coding: binary -*-
require 'rex/socket'

module Msf
module Session

###
#
# This class implements the Rex::Socket::Comm module interface and is capable
# of creating network-based connections that are pivoted from the session in
# question.
#
###
module Comm
  include Rex::Socket::Comm

  #
  # Session-based comm classes implement an instance specific method for
  # creating network-based connections rather than the typical class
  # specific methods.
  #
  def create(param)
    raise NotImplementedError
  end
end

end
end
