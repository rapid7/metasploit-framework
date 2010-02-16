class String
  if RUBY_VERSION < "1.9"
    def getbyte(index)
      self[index]
    end
  end
end