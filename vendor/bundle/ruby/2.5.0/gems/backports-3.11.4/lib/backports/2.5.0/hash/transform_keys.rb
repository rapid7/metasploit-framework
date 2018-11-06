class Hash
  def transform_keys
    return to_enum(:transform_keys){ size } unless block_given?
    h = {}
    each do |key, value|
      h[yield key] = value
    end
    h
  end unless method_defined? :transform_keys

  def transform_keys!
    return enum_for(:transform_keys!) { size } unless block_given?
    merge!({}) if frozen?
    keys.each do |key|
      self[yield(key)] = delete(key)
    end
    self
  end unless method_defined? :transform_keys!
end
