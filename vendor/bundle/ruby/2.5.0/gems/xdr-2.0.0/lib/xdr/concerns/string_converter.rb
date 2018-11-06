module XDR::Concerns::StringConverter
  def valid?(val)
    val.is_a?(String)
  end
end