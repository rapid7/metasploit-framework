unless Enumerable.method_defined? :minmax
  require 'backports/tools/arguments'

  module Enumerable
    def minmax
      return minmax{|a,b| a <=> b} unless block_given?
      first_time = true
      min, max = nil
      each do |object|
        if first_time
          min = max = object
          first_time = false
        else
          min = object if Backports.coerce_to_comparison(min, object, yield(min, object)) > 0
          max = object if Backports.coerce_to_comparison(max, object, yield(max, object)) < 0
        end
      end
      [min, max]
    end
  end
end
