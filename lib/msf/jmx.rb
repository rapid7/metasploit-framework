# -*- coding: binary -*-

require 'rex/java/serialization'

module Msf
  module Jmx
    require 'msf/jmx/util'
    require 'msf/jmx/discovery'
    require 'msf/jmx/handshake'
    require 'msf/jmx/mbean'

    include Msf::Jmx::Util
    include Msf::Jmx::Discovery
    include Msf::Jmx::Handshake
    include Msf::Jmx::Mbean

    def initialize(info = {})
      super

      register_options(
        [
          Msf::OptString.new('JMX_ROLE', [false, 'The role to interact with an authenticated JMX endpoint']),
          Msf::OptString.new('JMX_PASSWORD', [false, 'The password to interact with an authenticated JMX endpoint'])
        ], HTTP::Wordpress
      )
    end

    def jmx_role
      datastore['JMX_ROLE']
    end

    def jmx_password
      datastore['JMX_PASSWORD']
    end

  end
end
