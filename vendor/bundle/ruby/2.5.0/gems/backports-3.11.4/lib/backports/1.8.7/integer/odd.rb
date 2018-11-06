unless Integer.method_defined? :odd?
  class Integer
    def odd?
      !self[0].zero?
    end
  end
end
