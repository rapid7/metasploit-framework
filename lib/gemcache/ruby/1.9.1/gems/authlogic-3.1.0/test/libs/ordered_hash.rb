class Hash
  def each(&block)
    sorted_keys = keys.sort { |a, b| a.to_s <=> b.to_s }
    sorted_keys.each do |key|
      yield key, self[key]
    end
    self
  end
end