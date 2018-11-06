unless Hash.method_defined? :select!
  class Hash
    def select!
      return to_enum(:select!) unless block_given?
      raise "can't modify frozen hash" if frozen? # reject! won't do it for empty hashes...
      reject!{|key, value| ! yield key, value}
    end
  end
end
