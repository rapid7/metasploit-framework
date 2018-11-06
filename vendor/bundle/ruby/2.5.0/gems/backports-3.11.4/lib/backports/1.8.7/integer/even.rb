unless Integer.method_defined? :even?
  class Integer
    def even?
      self[0].zero?
    end
  end
end
