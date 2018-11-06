unless NilClass.method_defined? :to_h
  class NilClass
    def to_h
      {}
    end
  end
end
