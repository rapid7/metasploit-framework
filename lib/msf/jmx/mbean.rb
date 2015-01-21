# -*- coding: binary -*-

module Msf
  module Jmx
    module MBean
      require 'msf/jmx/mbean/server_connection'

      include Msf::Jmx::MBean::ServerConnection
    end
  end
end
