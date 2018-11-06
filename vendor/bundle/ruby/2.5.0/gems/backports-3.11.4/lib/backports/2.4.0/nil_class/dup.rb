class NilClass
  def dup
    self
  end
end if (nil.dup rescue true)
