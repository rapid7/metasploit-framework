unless Enumerable.method_defined? :count
  require 'backports/tools/arguments'

  module Enumerable
    def count(item = Backports::Undefined)
      seq = 0
      if item != Backports::Undefined
        each { |o| seq += 1 if item == o }
      elsif block_given?
        each { |o| seq += 1 if yield(o) }
      else
        each { seq += 1 }
      end
      seq
    end
  end
end
