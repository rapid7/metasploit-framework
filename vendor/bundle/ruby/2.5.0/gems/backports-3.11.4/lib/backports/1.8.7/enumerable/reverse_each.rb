unless Enumerable.method_defined? :reverse_each
  require 'enumerator'

  module Enumerable
    def reverse_each
      return to_enum(:reverse_each) unless block_given?
      # There is no other way then to convert to an array first... see 1.9's source.
      to_a.reverse_each{|e| yield e}
      self
    end
  end
end
