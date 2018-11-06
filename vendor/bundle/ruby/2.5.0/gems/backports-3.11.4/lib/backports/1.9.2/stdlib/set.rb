class Set
  def delete_if
    block_given? or return enum_for(__method__)
    to_a.each { |o| @hash.delete(o) if yield(o) }
    self
  end unless method_defined? :delete_if

  def keep_if
    block_given? or return enum_for(__method__)
    to_a.each { |o| @hash.delete(o) unless yield(o) }
    self
  end unless method_defined? :keep_if
end
