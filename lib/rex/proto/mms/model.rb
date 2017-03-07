# -*- coding: binary -*-

module Rex
  module Proto
    module Mms
      module Model

        GATEWAYS = {
          att:'mms.att.net',       # AT&T Wireless
          sprint: 'pm.sprint.com', # Sprint
          tmobile: 'tmomail.net',  # T-Mobile
          verizon: 'vzwpix.com'    # Verizon
        }

      end
    end
  end
end

require 'net/smtp'
require 'rex/proto/mms/model/smtp'
require 'rex/proto/mms/model/message'
require 'rex/proto/mms/client'
