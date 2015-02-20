# -*- coding: binary -*-

module Rex
  module Java
    # Include constants defining terminal and constant
    # values expected in a stream.
    module Serialization
      STREAM_MAGIC = 0xaced
      STREAM_VERSION = 5
      TC_NULL = 0x70
      TC_REFERENCE = 0x71
      TC_CLASSDESC = 0x72
      TC_OBJECT = 0x73
      TC_STRING = 0x74
      TC_ARRAY = 0x75
      TC_CLASS = 0x76
      TC_BLOCKDATA = 0x77
      TC_ENDBLOCKDATA = 0x78
      TC_RESET = 0x79
      TC_BLOCKDATALONG = 0x7A
      TC_EXCEPTION = 0x7B
      TC_LONGSTRING =  0x7C
      TC_PROXYCLASSDESC =  0x7D
      TC_ENUM =  0x7E
      BASE_WIRE_HANDLE = 0x7E0000

      SC_WRITE_METHOD = 0x01 # if SC_SERIALIZABLE
      SC_BLOCK_DATA = 0x08   # if SC_EXTERNALIZABLE
      SC_SERIALIZABLE = 0x02
      SC_EXTERNALIZABLE = 0x04
      SC_ENUM = 0x10

      PRIMITIVE_TYPE_CODES = {
        'B' => 'byte',
        'C' => 'char',
        'D' => 'double',
        'F' => 'float',
        'I' => 'int',
        'J' => 'long',
        'S' => 'short',
        'Z' => 'boolean'
      }

      OBJECT_TYPE_CODES = {
        '[' => 'array',
        'L' => 'object'
      }

      TYPE_CODES = PRIMITIVE_TYPE_CODES.merge(OBJECT_TYPE_CODES)
    end
  end
end

require 'rex/java/serialization/model'
require 'rex/java/serialization/builder'