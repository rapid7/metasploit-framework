unless Enumerable.method_defined? :one?
  module Enumerable
    def one?
      found_one = false
      if block_given?
        each do |o|
          if yield(o)
            return false if found_one
            found_one = true
          end
        end
      else
        each do |o|
          if o
            return false if found_one
            found_one = true
          end
        end
      end
      found_one
    end
  end
end
