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
    include Msf::Jmx::MBean
  end
end
