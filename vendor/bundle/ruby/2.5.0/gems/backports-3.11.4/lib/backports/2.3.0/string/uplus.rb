unless String.method_defined? :+@
  class String
    def +@
      frozen? ? dup : self
    end
  end
end
