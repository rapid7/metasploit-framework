# -*- coding: binary -*-

module Rex
  module Proto
    module Sms
      module Model

        GATEWAYS = {
          :alltel => 'sms.alltelwireless.com',   # Alltel
          :att    => 'txt.att.net',              # AT&T Wireless
          :boost  => 'sms.myboostmobile.com',    # Boost Mobile
          :cricket => 'sms.mycricket.com',       # Cricket Wireless
          # Sprint is commented out, because the gateways don't seem to work.
          # Gateways tried for Sprint:
          # messaging.sprintpcs.com
          # pm.sprint.com
          #:sprint  => 'messaging.sprintpcs.com', # Sprint
          :tmobile => 'tmomail.net',             # T-Mobile
          :verizon => 'vtext.com',               # Verizon
          :virgin  => 'vmobl.com',               # Virgin Mobile
          :google => 'msg.fi.google.com'         # Google Project Fi
        }

      end
    end
  end
end

require 'net/smtp'
require 'rex/proto/sms/model/smtp'
require 'rex/proto/sms/model/message'
require 'rex/proto/sms/client'
