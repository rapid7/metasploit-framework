# -*- coding: binary -*-

require 'rex/socket'
module Rex
  module Proto
    module MDNS
      class Server < Rex::Proto::DNS::Server
        def initialize(lhost = '0.0.0.0', lport = 5353, start_cache = false, res = nil, comm = nil, _ctx = {}, dblock = nil,
                       sblock = nil)
          super(lhost, lport, true, false, start_cache, res, comm, dblock, sblock)
        end

        def alias
          'mDNS Server'
        end
      end
    end
  end
end
