unless GC.respond_to? :stress
  def GC.stress
    false
  end

  def GC.stress=(flag)
    raise NotImplementedError
  end
end
