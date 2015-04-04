# -*- coding: binary -*-

module Msf
  module Java
    module Jmx
      # This module provides methods which help to handle data
      # used by Java JMX
      module Util

        # Extracts a Rex::Java::Serialization::Model::NewObject from
        # a Rex::Java::Serialization::Model::Stream
        #
        # @param stream [Rex::Java::Serialization::Model::Stream] the stream to extract the object from
        # @param id [Fixnum] the content position storing the object
        # @return [Rex::Java::Serialization::Model::NewObject, nil] the extracted object if success, nil otherwise
        def extract_object(stream, id)
          new_object = nil

          if stream.contents[id]
            new_object = stream.contents[id]
          else
            return nil
          end

          unless new_object.class == Rex::Java::Serialization::Model::NewObject
            return nil
          end

          new_object.class_desc.description.class_name.contents
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
          length = raw_length.unpack('n')[0]

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
          int = int_raw.unpack('N')[0]

          int
        end

        # Extracts an UnicastRef (endpoint) information from an IO
        #
        # @param io [IO] the io to extract the int from
        # @return [Hash, nil] the extracted int if success, nil otherwise
        def extract_unicast_ref(io)
          ref = extract_string(io)
          unless ref && ref == 'UnicastRef'
            return nil
          end

          address = extract_string(io)
          return nil unless address

          port = extract_int(io)
          return nil unless port

          id = io.read

          { address: address, port: port, id: id }
        end

      end
    end
  end
end
