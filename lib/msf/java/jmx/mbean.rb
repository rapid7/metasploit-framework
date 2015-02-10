# -*- coding: binary -*-

module Msf
  module Jmx
    module Mbean
      require 'msf/jmx/mbean/server_connection'

      include Msf::Jmx::Mbean::ServerConnection
    end
  end
end
