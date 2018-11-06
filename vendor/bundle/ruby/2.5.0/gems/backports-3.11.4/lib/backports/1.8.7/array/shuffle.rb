unless Array.method_defined? :shuffle
  class Array
    def shuffle
      dup.shuffle!
    end

    # Standard in Ruby 1.8.7+. See official documentation[http://ruby-doc.org/core-1.9/classes/Array.html]
    def shuffle!
      raise TypeError, "can't modify frozen array" if frozen?
      size.times do |i|
        r = i + Kernel.rand(size - i)
        self[i], self[r] = self[r], self[i]
      end
      self
    end
  end
end
