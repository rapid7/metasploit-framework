unless Hash.method_defined? :rassoc
  class Hash
    def rassoc(value)
      k = key(value)
      v = fetch(k){return nil}
      [k, fetch(k)] if k || v == value
    end
  end
end
