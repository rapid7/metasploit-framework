class Hash
  def hash
    h = 0
    each do |key, value|
      h ^= key.hash ^ value.hash
    end
    h
  end unless {}.hash == {}.hash

  def eql?(other)
    other.is_a?(Hash) &&
      size == other.size &&
      all? do |key, value|
        value.eql?(other.fetch(key){return false})
      end
  end unless {}.eql?({})
end
