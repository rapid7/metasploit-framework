require "xdr/version"
require "active_model"
require "active_support/concern"
require "active_support/dependencies/autoload"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/object/try"
require "active_support/core_ext/module/attribute_accessors"
require "active_support/core_ext/class/attribute"
require "active_support/core_ext/hash/indifferent_access"
require "active_support/core_ext/string/inflections"
require "active_support/logger"
require "active_support/ordered_hash"

module XDR
  extend ActiveSupport::Autoload

  MAX_SIZE = 2**32 - 1

  autoload :Namespace
  autoload :RPC
  autoload :DSL

  # Compound Type
  autoload :Struct
  autoload :Union
  autoload :Enum

  # Primitive Types
  autoload :Array
  autoload :Option
  autoload :Int
  autoload :UnsignedInt
  autoload :Hyper
  autoload :UnsignedHyper
  autoload :Float
  autoload :Double
  autoload :Quadruple
  autoload :Bool
  autoload :Opaque
  autoload :VarOpaque
  autoload :VarArray
  autoload :String
  autoload :Void

  # Validators
  autoload :StructValidator
  autoload :UnionValidator

  module Concerns
    extend ActiveSupport::Autoload
    autoload :ReadsBytes
    autoload :ConvertsToXDR
    autoload :IntegerConverter
    autoload :FloatConverter
    autoload :StringConverter
    autoload :ArrayConverter
  end

  class Error < StandardError ; end
  class ReadError < Error ; end
  class EnumValueError < ReadError ; end
  class EnumNameError < ReadError ; end
  class WriteError < Error ; end

  class InvalidSwitchError < Error ; end
  class InvalidValueError < Error ; end
  class ArmNotSetError < Error ; end

  mattr_accessor :logger
  self.logger = ActiveSupport::Logger.new(STDOUT)
  self.logger.level = Logger::WARN
end
