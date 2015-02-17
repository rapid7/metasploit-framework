# -*- coding: binary -*-

require 'rex/java/serialization'

module Msf
  module Java
    module Jmx
      require 'msf/java/jmx/util'
      require 'msf/java/jmx/discovery'
      require 'msf/java/jmx/handshake'
      require 'msf/java/jmx/mbean'

      include Msf::Java::Jmx::Util
      include Msf::Java::Jmx::Discovery
      include Msf::Java::Jmx::Handshake
      include Msf::Java::Jmx::Mbean

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
end
