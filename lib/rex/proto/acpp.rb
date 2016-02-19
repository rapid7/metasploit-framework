# -*- coding: binary -*-
#
# Support for the protocol used by Apple Airport products, typically on
# 5009/TCP.  This protocol is not documented and doesn't appear to have a name,
# so I'm calling it ACPP because that is the protocol header.
#

require 'rex/proto/acpp/client'
require 'rex/proto/acpp/message'

module Rex
  module Proto
    module ACPP
      DEFAULT_PORT = 5009
    end
  end
end
