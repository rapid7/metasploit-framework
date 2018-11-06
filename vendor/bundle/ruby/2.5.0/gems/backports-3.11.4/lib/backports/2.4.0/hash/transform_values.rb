class Hash
  def transform_values
    return to_enum(:transform_values){ size } unless block_given?
    h = {}
    each do |key, value|
      h[key] = yield value
    end
    h
  end unless method_defined? :transform_values

  def transform_values!
    return to_enum(:transform_values!){ size } unless block_given?
    reject!{} if frozen? # Force error triggerring if frozen, in case of empty array
    each do |key, value|
      self[key] = yield value
    end
  end unless method_defined? :transform_values!
end
