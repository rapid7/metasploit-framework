class Float
  def dup
    self
  end
end unless (0.0.dup rescue false)
