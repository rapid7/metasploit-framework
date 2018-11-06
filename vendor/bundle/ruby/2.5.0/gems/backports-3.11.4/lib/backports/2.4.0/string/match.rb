unless String.method_defined? :match?
  class String
    def match?(*args)
      !match(*args).nil?
    end
  end
end
