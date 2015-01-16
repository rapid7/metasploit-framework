# -*- coding: binary -*-

module Msf
  module Jmx
    require 'msf/jmx/discovery'
    require 'msf/jmx/handshake'
    require 'msf/jmx/mbean'

    include Msf::Jmx::Discovery
    include Msf::Jmx::Handshake
    include Msf::Jmx::MBean

    def get_instance_answer(stream)
      new_object = nil

      if stream.contents[1]
        new_object = stream.contents[1]
      else
        print_error("#{peer} - getObjectInstance returned an incorrect answer")
        return nil
      end

      unless new_object.class == Rex::Java::Serialization::Model::NewObject
        print_error("#{peer} - getObjectInstance didn't return a new object")
        return nil
      end

      new_object.class_desc.description.class_name.contents
    end

    def get_mbean_from_url_answer(stream)
      new_object = nil

      if stream.contents[3]
        new_object = stream.contents[3]
      else
        print_error("#{peer} - getMBeansFromURL returned an incorrect answer")
        return nil
      end

      unless new_object.class == Rex::Java::Serialization::Model::NewObject
        print_error("#{peer} - getMBeansFromURL didn't return a new object")
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
