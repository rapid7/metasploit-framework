# -*- coding: binary -*-
require 'rex/java/serialization'
require 'rex/text'
module Msf
  module Java
    module Rmi
      module Util
        # Calculates a method hash to make RMI calls as defined by the JDK 1.2
        #
        # @param signature [String] The remote method signature as specified by the JDK 1.2,
        #   method name + method descriptor (as explained in the Java Virtual Machine Specification)
        # @return [Fixnum] The method hash
        # @see http://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmi-stubs24.html The RemoteRef Interface documentation to understand how method hashes are calculated
        def calculate_method_hash(signature)
          utf = Rex::Java::Serialization::Model::Utf.new(nil, signature)
          sha1 = Rex::Text.sha1_raw(utf.encode)

          sha1.unpack('Q<')[0]
        end

        # Calculates an interface hash to make RMI calls as defined by the JDK 1.1
        #
        # @param methods [Array] set of method names and their descriptors
        # @param exceptions [Array] set of declared exceptions
        # @return [Fixnum] The interface hash
        # @see http://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmi-stubs24.html The RemoteRef Interface documentation to understand how interface hashes are calculated
        def calculate_interface_hash(methods, exceptions)
          stream = ''
          stream << [1].pack('N') # stub version number

          methods.each do |m|
            utf_method = Rex::Java::Serialization::Model::Utf.new(nil, m[:name])
            utf_descriptor = Rex::Java::Serialization::Model::Utf.new(nil, m[:descriptor])
            stream << utf_method.encode
            stream << utf_descriptor.encode
            exceptions.each do |e|
              utf_exception = Rex::Java::Serialization::Model::Utf.new(nil, e)
              stream << utf_exception.encode
            end
          end

          sha1 = Rex::Text.sha1_raw(stream)

          sha1.unpack('Q<')[0]
        end
      end
    end
  end
end
