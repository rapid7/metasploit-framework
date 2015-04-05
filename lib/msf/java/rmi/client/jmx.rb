# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Jmx
          require 'msf/java/rmi/client/jmx/server'
          require 'msf/java/rmi/client/jmx/connection'

          include Msf::Java::Rmi::Client::Jmx::Server
          include Msf::Java::Rmi::Client::Jmx::Connection

          OBJECT_NAME_UID = 1081892073854801359
          BYTE_ARRAY_UID = -5984413125824719648
          MARSHALLED_OBJECT_UID = 8988374069173025854
          STRING_ARRAY_UID = -5921575005990323385
          OBJECT_ARRAY_UID = -8012369246846506644
        end
      end
    end
  end
end
