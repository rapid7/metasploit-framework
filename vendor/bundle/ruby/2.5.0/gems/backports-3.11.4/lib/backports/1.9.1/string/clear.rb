unless String.method_defined? :clear
  class String
    def clear
      self[0,length] = ""
      self
    end
  end
end
