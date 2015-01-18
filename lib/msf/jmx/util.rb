# -*- coding: binary -*-

module Msf
  module Jmx
    module Util

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

      def extract_int(io)
        int_raw = io.read(4)
        unless int_raw && int_raw.length == 4
          return nil
        end
        int = int_raw.unpack('N')[0]

        int
      end
    end
  end
end
