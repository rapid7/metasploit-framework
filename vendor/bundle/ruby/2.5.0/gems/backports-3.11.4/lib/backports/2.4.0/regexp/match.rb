unless Regexp.method_defined? :match?
  class Regexp
    def match?(*args)
      !match(*args).nil?
    end
  end
end
