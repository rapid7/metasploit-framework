unless Integer.method_defined? :ord
  class Integer
    def ord
      self
    end
  end
end
