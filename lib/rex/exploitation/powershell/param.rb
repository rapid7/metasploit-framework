# -*- coding: binary -*-

require 'zlib'
require 'rex/text'

module Rex
module Exploitation

module Powershell

  class Param
    attr_accessor :klass, :name
    def initialize(klass,name)
      @klass = klass.strip.gsub(/\[|\]|\s/,'')
      @name = name.strip.gsub(/\s|,/,'')
    end

    #
    # To String
    #
    # @return [String] Powershell param
    def to_s
      "[#{klass}]$#{name}"
    end
  end

end
end
end

