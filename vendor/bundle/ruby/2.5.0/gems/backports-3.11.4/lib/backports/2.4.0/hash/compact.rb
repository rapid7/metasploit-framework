class Hash
  def compact
    h = {}
    each do |key, value|
      h[key] = value unless value == nil
    end
    h
  end unless method_defined? :compact

  def compact!
    reject! {|_key, value| value == nil}
  end unless method_defined? :compact!
end
