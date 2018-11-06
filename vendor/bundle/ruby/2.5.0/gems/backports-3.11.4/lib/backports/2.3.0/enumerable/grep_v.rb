unless Enumerable.method_defined? :grep_v
  require 'backports/1.9.2/enumerable/each_entry'

  module Enumerable
    def grep_v(pattern)
      if block_given?
        acc = []
        each_entry do |v|
          acc << yield(v) unless pattern === v
        end
        acc
      else
        reject {|v| pattern === v }
      end
    end
  end
end
