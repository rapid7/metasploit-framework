unless Enumerable.method_defined? :minmax_by
  require 'backports/tools/extreme_object'
  require 'enumerator'

  module Enumerable
    # Standard in Ruby 1.8.7+. See official documentation[http://ruby-doc.org/core-1.9/classes/Enumerable.html]
    def minmax_by
      return to_enum(:minmax_by) unless block_given?
      min_object, min_result = nil, Backports::MOST_EXTREME_OBJECT_EVER
      max_object, max_result = nil, Backports::MOST_EXTREME_OBJECT_EVER
      each do |object|
        result = yield object
        min_object, min_result = object, result if min_result > result
        max_object, max_result = object, result if max_result < result
      end
      [min_object, max_object]
    end
  end
end
