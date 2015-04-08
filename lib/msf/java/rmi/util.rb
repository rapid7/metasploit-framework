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
        def calculate_interface_hash(methods)
          stream = ''
          stream << [1].pack('N') # stub version number

          methods.each do |m|
            utf_method = Rex::Java::Serialization::Model::Utf.new(nil, m[:name])
            utf_descriptor = Rex::Java::Serialization::Model::Utf.new(nil, m[:descriptor])
            stream << utf_method.encode
            stream << utf_descriptor.encode
            m[:exceptions].each do |e|
              utf_exception = Rex::Java::Serialization::Model::Utf.new(nil, e)
              stream << utf_exception.encode
            end
          end

          sha1 = Rex::Text.sha1_raw(stream)

          sha1.unpack('Q<')[0]
        end

        # Extracts an string from an IO
        #
        # @param io [IO] the io to extract the string from
        # @return [String, nil] the extracted string if success, nil otherwise
        def extract_string(io)
          raw_length = io.read(2)
          unless raw_length && raw_length.length == 2
            return nil
          end
          length = raw_length.unpack('s>')[0]

          string = io.read(length)
          unless string && string.length == length
            return nil
          end

          string
        end

        # Extracts an int from an IO
        #
        # @param io [IO] the io to extract the int from
        # @return [Fixnum, nil] the extracted int if success, nil otherwise
        def extract_int(io)
          int_raw = io.read(4)
          unless int_raw && int_raw.length == 4
            return nil
          end
          int = int_raw.unpack('l>')[0]

          int
        end

        # Extracts a long from an IO
        #
        # @param io [IO] the io to extract the long from
        # @return [Fixnum, nil] the extracted int if success, nil otherwise
        def extract_long(io)
          int_raw = io.read(8)
          unless int_raw && int_raw.length == 8
            return nil
          end
          int = int_raw.unpack('q>')[0]

          int
        end

        # Extract an RMI interface reference from an IO
        #
        # @param io [IO] the io to extract the reference from, should contain the data
        #   inside a BlockData with the reference information.
        # @return [Hash, nil] the extracted reference if success, nil otherwise
        # @see Msf::Java::Rmi::Client::Jmx:Server::Parser#parse_jmx_new_client_endpoint
        # @see Msf::Java::Rmi::Client::Registry::Parser#parse_registry_lookup_endpoint
        def extract_reference(io)
          ref = extract_string(io)
          unless ref && ref == 'UnicastRef'
            return nil
          end

          address = extract_string(io)
          return nil unless address

          port = extract_int(io)
          return nil unless port

          object_number = extract_long(io)

          uid = Rex::Proto::Rmi::Model::UniqueIdentifier.decode(io)

          {address: address, port: port, object_number: object_number, uid: uid}
        end
      end
    end
  end
end
