unless String.method_defined? :codepoints
  class String
    def codepoints
      return to_enum(:codepoints) unless block_given?
      unpack("U*").each{|cp| yield cp}
    end
  end
end
