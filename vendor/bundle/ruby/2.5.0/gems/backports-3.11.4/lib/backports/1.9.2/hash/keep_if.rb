unless Hash.method_defined? :keep_if
  class Hash
    def keep_if
      return to_enum(:keep_if) unless block_given?
      delete_if{|key, value| ! yield key, value}
    end
  end
end
