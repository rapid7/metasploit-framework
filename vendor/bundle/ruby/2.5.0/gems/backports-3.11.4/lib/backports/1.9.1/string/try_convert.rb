unless String.respond_to? :try_convert
  require 'backports/tools/arguments'

  def String.try_convert(x)
    Backports.try_convert(x, String, :to_str)
  end
end
