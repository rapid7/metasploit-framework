module XDR::Concerns::ArrayConverter
  def valid?(val)
    val.is_a?(Array) && val.all?{|v| @child_type.valid?(v)}
  end
end