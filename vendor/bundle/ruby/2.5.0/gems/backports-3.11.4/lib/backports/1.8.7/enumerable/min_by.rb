unless Enumerable.method_defined? :min_by
  require 'backports/tools/extreme_object'
  require 'enumerator'

  module Enumerable
    def min_by
      return to_enum(:min_by) unless block_given?
      min_object, min_result = nil, Backports::MOST_EXTREME_OBJECT_EVER
      each do |object|
        result = yield object
        min_object, min_result = object, result if min_result > result
      end
      min_object
    end
  end
end
