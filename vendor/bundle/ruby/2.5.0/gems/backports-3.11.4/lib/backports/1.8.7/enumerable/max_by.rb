unless Enumerable.method_defined? :max_by
  require 'backports/tools/extreme_object'
  require 'enumerator'

  module Enumerable
    def max_by
      return to_enum(:max_by) unless block_given?
      max_object, max_result = nil, Backports::MOST_EXTREME_OBJECT_EVER
      each do |object|
        result = yield object
        max_object, max_result = object, result if max_result < result
      end
      max_object
    end
  end
end
