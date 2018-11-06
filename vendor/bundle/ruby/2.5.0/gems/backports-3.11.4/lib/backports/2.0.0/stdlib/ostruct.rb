class OpenStruct
  def [](name)
    @table[name.to_sym]
  end unless method_defined? :[]

  def []=(name, value)
    modifiable[new_ostruct_member(name)] = value
  end unless method_defined? :[]=

  def eql?(other)
    return false unless other.kind_of?(OpenStruct)
    @table.eql?(other.table)
  end unless method_defined? :eql?

  def hash
    @table.hash
  end unless method_defined? :hash

  def each_pair
    return to_enum(:each_pair) unless block_given?
    @table.each_pair{|p| yield p}
  end unless method_defined? :each_pair

  def to_h
    @table.dup
  end unless method_defined? :to_h
end
