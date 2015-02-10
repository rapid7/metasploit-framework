# -*- coding: binary -*-

module Msf
  module Java
    module Jmx
      module Mbean
        require 'msf/java/jmx/mbean/server_connection'

        include Msf::Jmx::Mbean::ServerConnection
      end
    end
  end
end
