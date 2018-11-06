unless Array.respond_to? :try_convert
  require 'backports/tools/arguments'

  def Array.try_convert(obj)
    Backports.try_convert(obj, Array, :to_ary)
  end
end
