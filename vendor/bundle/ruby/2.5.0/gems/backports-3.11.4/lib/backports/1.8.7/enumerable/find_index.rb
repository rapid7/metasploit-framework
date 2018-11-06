unless Enumerable.method_defined? :find_index
  require 'backports/tools/arguments'
  require 'enumerator'

  module Enumerable
    def find_index(obj = Backports::Undefined)
      if obj != Backports::Undefined
        each_with_index do |element, i|
          return i if element == obj
        end
      elsif block_given?
        each_with_index do |element, i|
          return i if yield element
        end
      else
        return to_enum(:find_index)
      end
      nil
    end
  end
end
