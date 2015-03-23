# -*- coding: binary -*-

module Msf
  module Java
    module Rmi
      module Client
        module Registry
          require 'msf/java/rmi/client/jmx/server'
          require 'msf/java/rmi/client/jmx/connection'

          include Msf::Java::Rmi::Client::Jmx::Server
          include Msf::Java::Rmi::Client::Jmx::Connection
        end
      end
    end
  end
end
