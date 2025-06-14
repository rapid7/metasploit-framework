# -*- coding: binary -*-

###
#
# This class is here to implement advanced features for linux-based
# payloads. Linux payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Linux
  #
  # This mixin is chained within payloads that target the Linux platform.
  # It provides special prepends, to support things like chroot and setuid.
  #

  def initialize(info = {})
    super(info)
  end

end
