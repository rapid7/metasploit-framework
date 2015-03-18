# -*- coding: binary -*-

module Msf
  module Java
    module Jmx
      # This module provides methods which help to handle JMX end points discovery
      module Discovery
        # Builds a Rex::Proto::Rmi::Model::Call to discover
        # an JMX RMI endpoint
        #
        # @return [Rex::Proto::Rmi::Model::Call]
        # @TODO it should be moved to a Registry mixin
        def discovery_stream
          call = build_call(
            object_number: 0,
            uid_number: 0,
            uid_time: 0,
            uid_count: 0,
            operation: 2, # java.rmi.Remote lookup(java.lang.String)
            hash: 0x44154dc9d4e63bdf, #ReferenceRegistryStub
            arguments: [Rex::Java::Serialization::Model::Utf.new(nil, 'jmxrmi')]
          )

          call
        end
      end
    end
  end
end
