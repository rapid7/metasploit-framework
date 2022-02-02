# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for Denial of Service attacks
#
###

module Auxiliary::Dos


# Never include DoS modules in automated attacks
def autofilter
  false
end

end
end
