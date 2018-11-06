class Fixnum
  def dup
    self
  end
end unless (0.dup rescue false)
