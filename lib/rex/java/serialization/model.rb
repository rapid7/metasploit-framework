# -*- coding: binary -*-

module Rex
  module Java
    module Serialization
      module Model

        autoload :Annotation,     'rex/java/serialization/model/annotation'
        autoload :BlockDataLong,  'rex/java/serialization/model/block_data_long'
        autoload :BlockData,      'rex/java/serialization/model/block_data'
        autoload :ClassDesc,      'rex/java/serialization/model/class_desc'
        autoload :Contents,       'rex/java/serialization/model/contents'
        autoload :Element,        'rex/java/serialization/model/element'
        autoload :EndBlockData,   'rex/java/serialization/model/end_block_data'
        autoload :Field,          'rex/java/serialization/model/field'
        autoload :LongUtf,        'rex/java/serialization/model/long_utf'
        autoload :NewArray,       'rex/java/serialization/model/new_array'
        autoload :ProxyClassDesc, 'rex/java/serialization/model/proxy_class_desc'
        autoload :NewClassDesc,   'rex/java/serialization/model/new_class_desc'
        autoload :NewEnum,        'rex/java/serialization/model/new_enum'
        autoload :NewObject,      'rex/java/serialization/model/new_object'
        autoload :NullReference,  'rex/java/serialization/model/null_reference'
        autoload :Reference,      'rex/java/serialization/model/reference'
        autoload :Reset,          'rex/java/serialization/model/reset'
        autoload :Stream,         'rex/java/serialization/model/stream'
        autoload :Utf,            'rex/java/serialization/model/utf'

      end
    end
  end
end

