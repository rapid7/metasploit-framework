require 'thread'

class String
  if RUBY_VERSION < "1.9"
    def getbyte(index)
      self[index]
    end

    def setbyte(index, c)
      self[index] = c
    end
  end
end
