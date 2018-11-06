class TrueClass
  def dup
    self
  end
end unless (true.dup rescue false)

