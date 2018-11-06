unless Struct.method_defined? :to_h
  class Struct
    def to_h
      h = {}
      self.class.members.each{|m| h[m.to_sym] = self[m]}
      h
    end
  end
end
