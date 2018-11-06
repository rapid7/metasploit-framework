unless Integer.method_defined? :pred
  class Integer
    def pred
      self - 1
    end
  end
end
