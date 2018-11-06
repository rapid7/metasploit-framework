unless Hash.method_defined? :to_h
  class Hash
    def to_h
      self.class == Hash ? self : {}.replace(self)
    end
  end
end
