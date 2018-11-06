unless Enumerable.method_defined?(:to_h)
  require 'backports/tools/arguments'
  module Enumerable
    def to_h(*args)
      h = {}
      each_entry(*args) do |key_value|
        key_value = Backports.coerce_to_ary(key_value)
        if key_value.size != 2
          raise ArgumentError, "element has wrong array length (expected 2, was #{key_value.size})"
        end
        h[ key_value[0] ] = key_value[1]
      end
      h
    end
  end
end
