class Array
  unless method_defined? :sample
    def sample(arr = nil)
      # based on code from https://github.com/marcandre/backports
      size = length
      return self[Kernel.rand(size)] if arr.nil?

      arr = arr.to_int
      raise ArgumentError, 'negative array size' if arr < 0

      arr = size if arr > size

      result = Array.new(self)
      arr.times do |i|
        r = i + Kernel.rand(size - i)
        result[i], result[r] = result[r], result[i]
      end
      result[arr..size] = []
      result
    end
  end
end
