module FactoryBot
  class Decorator < BasicObject
    undef_method :==

    def initialize(component)
      @component = component
    end

    def method_missing(name, *args, &block)
      @component.send(name, *args, &block)
    end

    def send(symbol, *args, &block)
      __send__(symbol, *args, &block)
    end

    def self.const_missing(name)
      ::Object.const_get(name)
    end
  end
end
