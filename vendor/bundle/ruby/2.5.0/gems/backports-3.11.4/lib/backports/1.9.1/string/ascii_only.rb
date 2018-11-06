unless String.method_defined? :ascii_only?
  class String
    def ascii_only?
      !(self =~ /[^\x00-\x7f]/)
    end
  end
end
